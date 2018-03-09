#!/usr/bin/env python
"""
CGNX API -> syslog implementation

cg-syslog-apigw@ebob9.com

"""
# standard modules
import argparse
import logging
from logging.handlers import SysLogHandler
import json
import re
import datetime
import collections
import time
import sys
import socket
from copy import deepcopy

# CloudGenix Python SDK
try:
    import cloudgenix
except ImportError as e:
    print("ERROR: 'cloudgenix' python module required. (try 'pip install cloudgenix').\n {}".format(e))
    sys.exit(1)

# IDname for CloudGenix
try:
    from cloudgenix_idname import generate_id_name_map
except ImportError as e:
    print("ERROR: 'cloudgenix-idnane' python module required. (try 'pip install cloudgenix-idname').\n {}".format(e))
    sys.exit(1)

# Global Vars
ACCEPTABLE_FACILITY = ['auth', 'authpriv', 'cron', 'daemon', 'ftp', 'kern', 'lpr', 'mail', 'news', 'syslog',
                       'user', 'uucp', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7']
DEFAULT_TIME_BETWEEN_API_UPDATES = 300  # seconds
DEFAULT_COLD_START_SEND_OLD_EVENTS = 24 # hours
TIME_BETWEEN_LOGIN_ATTEMPTS = 300  # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7  # hours
SYSLOG_GW_VERSION = "1.0.0"
EMIT_TCP_SYSLOG = False
SYSLOG_DATE_FORMAT = '%b %d %H:%M:%S'
RFC5424 = False
RFC5424_HOSTNAME = "cg-syslog-apigw"
LEGACY_EVENTS_API = False

# Set NON-SYSLOG logging to use function name
clilogger = logging.getLogger(__name__)

# Generic structure to keep authentication info
sdk_vars = {
    "selected_element_id": None,  # Selected Element ID
    "selected_site_id": None,  # Selected Site ID
    "emit_json": None,  # Emit syslog as JSON instead of text.
    "audit_event_start": datetime.datetime.utcnow() - datetime.timedelta(hours=24),  # this gets updated by arg vars.
    "alarm_event_start": datetime.datetime.utcnow() - datetime.timedelta(hours=24),  # this gets updated by arg vars.
    "alert_event_start": datetime.datetime.utcnow() - datetime.timedelta(hours=24),  # this gets updated by arg vars.
    "disable_name": False,  # Disable name parsing, this gets updated by arg vars
    "disable_operator": False,  # Disable audit event parsing, this gets updated by arg vars
    "disable_audit": False,  # Disable audit event parsing, this gets updated by arg vars
    "disable_alert": False,  # Disable alert event parsing, this gets updated by arg vars
    "disable_alarm": False,  # Disable alarm parsing, this gets updated by arg vars
    "ignore_operator": [],  # Ignore list for Audits, loaded from cloudgenix_settings.py
    "ignore_audit": [],  # Ignore list for Audits, loaded from cloudgenix_settings.py
    "ignore_alarm": [],  # Ignore list for Alarm, loaded from cloudgenix_settings.py
    "ignore_alert": []  # Ignore list for Alert, loaded from cloudgenix_settings.py
}


def update_parse_operator(last_reported_event, sdk_vars):
    """
    Get operator from tenant.
    :param sdk_vars: sdk_vars global info struct
    :param last_reported_event: datetime.datetime of the oldest event reported.
    :return: status (boolean), parsed_events (event report struct), json_events (events list in json)
    """
    latest_event = last_reported_event
    current_datetime_mark = datetime.datetime.utcnow()
    current_time_mark = current_datetime_mark.isoformat() + 'Z'
    parsed_events = []

    # add 1 second to make sure we don't get the same event over and over)
    start_time = (last_reported_event + datetime.timedelta(seconds=1)).isoformat() + 'Z'

    operator_list = []
    raw_operator_log = []

    operator_resp = sdk.get.operators_t()
    status_operator = operator_resp.cgx_status
    raw_operators = operator_resp.cgx_content
    status_code = operator_resp.status_code

    if not status_operator or type(raw_operators) is not dict:
        # error, return empty.
        # This response will trigger a relogin attempt to mitigate multi-token refresh scenarios.
        return False, last_reported_event, [], 0, status_code

    operator_id_list = raw_operators.get('items', [])

    for operator_dict in operator_id_list:
        operator_id = operator_dict.get('id')
        if operator_id:
            # get operator events
            session_resp = sdk.get.operator_sessions(operator_id)
            status_id = session_resp.cgx_status
            raw_id = session_resp.cgx_content

            if not status_id or type(raw_id) is not dict:
                # look for blank response, this is ok.
                if session_resp.status_code in [404]:
                    # 404 means no operator session log.
                    continue
                # error, return empty.
                # This response will trigger a relogin attempt to mitigate multi-token refresh scenarios.
                return False, last_reported_event, [], 0, session_resp.status_code

            raw_operator_items = raw_id.get('items', [])
            # append to full log.
            for event in raw_operator_items:
                event['operator_id'] = operator_id
                raw_operator_log.append(event)

    # iterate through operators
    if status_operator:
        raw_operator_items = raw_operator_log

        parsed_operator_items = []

        # manipulate the log into a standard event format
        for d in raw_operator_items:
            inactive = d.get('inactive')
            inactive_reason = d.get('inactive_reason')
            d.pop('inactive', None)
            d.pop('inactive_reason', None)
            d['sess_inactive'] = inactive
            d['sess_inactive_reason'] = inactive_reason

            disabled = d.get('disabled')
            disabled_reason = d.get('disabled_reason')
            d.pop('disabled', None)
            d.pop('disabled_reason', None)
            d['sess_disabled'] = disabled
            d['sess_disabled_reason'] = disabled_reason

            if inactive or disabled:
                d['status'] = "LOGGED_OUT"
            else:
                d['status'] = "LOGGED_IN"

            d['login_time'] = d.get('_created_on_utc')
            d['event_time'] = d.get('_updated_on_utc')

            if not disabled:
                d.pop('sess_disabled_reason', None)
            if not inactive:
                d.pop('sess_inactive_reason', None)

            # parse user agent
            for user_agent_key, user_agent_value in d.get('user_agent', {}).iteritems():
                d['user_agent_' + user_agent_key] = str(user_agent_value)
            d.pop('user_agent', None)

            # remove '_' prefixed keys in operators.
            for k in d.keys():
                if k.startswith('_'):
                    del d[k]

            # Get time of request.
            event_timestamp = d.get('event_time', 0)
            # Get request type for code insertion
            request_type = d.get('status')
            # if no timestamp, set to NOW so event will definitely be emitted.
            if event_timestamp:
                operator_request_datetime = datetime.datetime.utcfromtimestamp(int(event_timestamp) / 10000000.0)
            else:
                operator_request_datetime = current_datetime_mark

            # print "TIME WTF: ", int(event_timestamp) / 1000000.0
            # print "OPERATOR_REQUEST_DATETIME: ", operator_request_datetime.isoformat() + 'Z'
            # print "LAST_REPORTED_EVENT:  ", last_reported_event.isoformat() + 'Z'
            # print " > ", (operator_request_datetime > last_reported_event)

            # Since operator log is long back, make sure log is in request window.
            if operator_request_datetime > last_reported_event:
                # add timestamp for sorting
                d['time'] = operator_request_datetime.isoformat() + 'Z'
                # add to parsing list.
                parsed_operator_items.append(d)

        # add current alarms to list
        operator_list.extend(parsed_operator_items)

    if not operator_list:
        # Valid transaction, but no data. Return empty.
        return True, last_reported_event, [], 0, status_code

    # combine lists
    combined_list = []
    combined_list.extend(operator_list)

    # sort by create time
    events_list = sorted(combined_list, key=lambda k: k["time"])

    # parse events
    for event in events_list:

        discard_event = False

        event_dict = collections.OrderedDict()

        event_type = event.get('type', '')

        # This is for Operator log event parsing.
        event_timestamp = event.get('event_time')
        syslogdate = "NO_TIME_REPORTED"
        if event_timestamp:

            # convert to datetime
            event_datetime = datetime.datetime.utcfromtimestamp(int(event_timestamp) / 10000000.0)
            syslogdate = event_datetime.strftime(SYSLOG_DATE_FORMAT)

            # if no latest event or event is newer, update.
            if not latest_event:
                # print "Updating '{0}' to '{1}'.".format(str(latest_event),
                #                                     event_datetime.strftime("%b %d %Y %H:%M:%S"))
                latest_event = event_datetime
            elif event_datetime > latest_event:
                # print "Updating '{0}' to '{1}'.".format(latest_event.strftime("%b %d %Y %H:%M:%S"),
                #                                     event_datetime.strftime("%b %d %Y %H:%M:%S"))
                latest_event = event_datetime

        info_string = ""
        for key, value in event.iteritems():
            if type(value) is list:
                info_string = info_string + key.upper() + ": " + str(",".join(value)) + " "
            else:
                info_string = info_string + key.upper() + ": " + str(value) + " "

        # find out if this operator event should be ignored.

        # start adding items to ordered dict
        # xlate siteid to name, if exists
        event_operatorid = event.get('operator_id', '')
        event_siteid = event.get('site_id', '')

        if sdk_vars.get('emit_json'):
            # try to translate to name - if no name return site id, or UNKNOWN if no ID in message.
            event_dict['operator'] = event_operatorid

            event_dict['type'] = 'operator'
            # just populate the message as raw JSON.
            event_dict['info'] = json.dumps(event)

        elif RFC5424:
            # Strict RFC5424
            # set type to operator
            event_dict['type'] = 'operator'

            event_dict['cloudgenix_host'] = RFC5424_HOSTNAME

            # try to translate to name - if no name return site id, or UNKNOWN if no ID in message.
            event_dict['site'] = id_map.get(event_siteid, event_siteid)

            # try to translate to name - if no name return site id, or UNKNOWN if no ID in message.
            event_dict['operator'] = id_map.get(event_operatorid, event_operatorid)
            event_dict['device_time'] = syslogdate
            event_dict['severity'] = event.get('severity', 'info')
            event_dict['correlation'] = event.get('correlation_id', '')
            # for RFC5424, pass everything as key/value.
            event_dict.update(event)

        else:
            # Normal text SYSLOG.
            # try to translate to name - if no name return site id, or UNKNOWN if no ID in message.
            event_dict['operator'] = event_operatorid

            event_dict['severity'] = 'info'
            event_dict['type'] = 'operator'
            event_dict['info'] = info_string

        parsed_events.append(event_dict)

    # print json.dumps(parsed_events, indent=4)
    #
    # print repr(latest_event)

    return True, latest_event, parsed_events, len(operator_list), status_code


def update_parse_audit(last_reported_event, sdk_vars):
    """
    Get audit from tenant.
    :param sdk_vars: sdk_vars global info struct
    :param last_reported_event: datetime.datetime of the oldest event reported.
    :return: status (boolean), parsed_events (event report struct), json_events (events list in json)
    """
    latest_event = last_reported_event
    current_datetime_mark = datetime.datetime.utcnow()
    current_time_mark = current_datetime_mark.isoformat() + 'Z'
    parsed_events = []

    # add 1 second to make sure we don't get the same event over and over)
    start_time = (last_reported_event + datetime.timedelta(seconds=1)).isoformat() + 'Z'

    audit_list = []

    # get events from last event.
    audit_resp = sdk.get.tenant_access()
    status_audit = audit_resp.cgx_status
    raw_audit = audit_resp.cgx_content
    status_code = audit_resp.status_code

    if not status_audit or type(raw_audit) is not dict:
        # error, return empty.
        # This response will trigger a relogin attempt to mitigate multi-token refresh scenarios.
        return False, last_reported_event, [], 0, status_code

    # iterate through audits
    if status_audit:
        raw_audit_items = raw_audit.get('items', [])

        parsed_audit_items = []

        # manipulate the log into a standard event format
        for d in raw_audit_items:
            # remove '_' prefixed keys in audits.
            for k in d.keys():
                if k.startswith('_'):
                    del d[k]
            # remove response body, as it is too long for syslog
            del d['response_body']
            # Get time of request.
            event_timestamp = d.get('request_ts', 0)
            # Get request type for code insertion
            request_type = d.get('request_type', 'generic')
            # if no timestamp, set to NOW so event will definitely be emitted.
            if event_timestamp:
                audit_request_datetime = datetime.datetime.utcfromtimestamp(event_timestamp / 1000.0)
            else:
                audit_request_datetime = current_datetime_mark

            # print "AUDIT_REQUEST_DATETIME: ", audit_request_datetime.isoformat() + 'Z'
            # print "LAST_REPORTED_EVENT:  ", last_reported_event.isoformat() + 'Z'
            # print " > ", (audit_request_datetime > last_reported_event)

            # Since audit log is long back, make sure log is in request window.
            if audit_request_datetime > last_reported_event:
                # add timestamp for sorting
                d['code'] = ("audit_" + str(request_type)).upper()
                d['time'] = audit_request_datetime.isoformat() + 'Z'
                # add to parsing list.
                parsed_audit_items.append(d)

        # add current alarms to list
        audit_list.extend(parsed_audit_items)

    if not audit_list:
        # Valid transaction, but no data. Return empty.
        return True, last_reported_event, [], 0, status_code

    # combine lists
    combined_list = []
    combined_list.extend(audit_list)

    # sort by create time
    events_list = sorted(combined_list, key=lambda k: k["time"])

    # parse events
    for event in events_list:

        discard_event = False

        event_dict = collections.OrderedDict()

        event_type = event.get('type', '')

        # This is for Audit log event parsing.
        event_timestamp = event.get('request_ts')
        syslogdate = "NO_TIME_REPORTED"
        if event_timestamp:

            # convert to datetime
            event_datetime = datetime.datetime.utcfromtimestamp(event_timestamp / 1000.0)
            syslogdate = event_datetime.strftime(SYSLOG_DATE_FORMAT)

            # if no latest event or event is newer, update.
            if not latest_event:
                # print "Updating '{0}' to '{1}'.".format(str(latest_event),
                #                                     event_datetime.strftime("%b %d %Y %H:%M:%S"))
                latest_event = event_datetime
            elif event_datetime > latest_event:
                # print "Updating '{0}' to '{1}'.".format(latest_event.strftime("%b %d %Y %H:%M:%S"),
                #                                     event_datetime.strftime("%b %d %Y %H:%M:%S"))
                latest_event = event_datetime

        info_string = ""
        for key, value in event.iteritems():
            if type(value) is list:
                info_string = info_string + key.upper() + ": " + str(",".join(value)) + " "
            else:
                info_string = info_string + key.upper() + ": " + str(value) + " "

        # pull code and reference for filtering
        code = event.get('code', '')
        reference = event.get('request_url', "none")
        event_id = event.get('id', '')

        # find out if this audit event should be ignored.
        for regex_search in sdk_vars['ignore_audit']:
            # if discard is already determined, bypass loop logic.
            if discard_event:
                continue

            # check code then reference for match
            code_check = regex_search.match(code)
            reference_check = regex_search.match(reference)

            if code_check:
                clilogger.debug("DISCARD: Audit {0} discarded due to code '{1}' matching '{2}'."
                                "".format(event_id, code, regex_search.pattern))
                discard_event = True
            elif reference_check:
                clilogger.debug("DISCARD: Audit {0} discarded due to reference '{1}' matching '{2}'."
                                "".format(event_id, reference, regex_search.pattern))
                discard_event = True
            else:
                clilogger.debug("PARSE: Audit {0} kept due to no match of code '{1}' or reference '{2}' to '{3}'"
                                .format(event_id, code, reference, regex_search.pattern))

        if not discard_event:
            reference_string = "REFERENCE: " + str(reference)

            # start adding items to ordered dict
            # xlate siteid to name, if exists
            event_operatorid = event.get('operator_id', '')
            event_siteid = event.get('site_id', '')

            if sdk_vars.get('emit_json'):
                # try to translate to name - if no name return site id, or UNKNOWN if no ID in message.
                event_dict['operator'] = event_operatorid

                event_dict['type'] = 'audit'
                # just populate the message as raw JSON.
                event_dict['info'] = json.dumps(event)

            elif RFC5424:
                # Strict RFC5424
                # set type to audit
                event_dict['type'] = 'audit'

                event_dict['cloudgenix_host'] = RFC5424_HOSTNAME

                # try to translate to name - if no name return site id, or UNKNOWN if no ID in message.
                event_dict['site'] = id_map.get(event_siteid, event_siteid)

                # try to translate to name - if no name return site id, or UNKNOWN if no ID in message.
                event_dict['operator'] = id_map.get(event_operatorid, event_operatorid)
                event_dict['code'] = code
                event_dict['device_time'] = syslogdate
                event_dict['severity'] = event.get('severity', 'info')
                event_dict['correlation'] = event.get('correlation_id', '')
                event_dict['reference'] = str(reference)
                # for RFC5424, pass everything as key/value.
                event_dict.update(event)

            else:
                # Normal text SYSLOG.
                # try to translate to name - if no name return site id, or UNKNOWN if no ID in message.
                event_dict['operator'] = event_operatorid

                event_dict['severity'] = 'info'
                event_dict['type'] = 'audit'
                event_dict['info'] = reference_string + " " + info_string

            parsed_events.append(event_dict)

    # print json.dumps(parsed_events, indent=4)
    #
    # print repr(latest_event)

    return True, latest_event, parsed_events, len(audit_list), status_code


def update_parse_alarm(last_reported_event, sdk_vars):
    """
    Get events from tenant.
    :param sdk_vars: sdk_vars global info struct
    :param last_reported_event: datetime.datetime of the oldest event reported.
    :return: status (boolean), parsed_events (event report struct), json_events (events list in json)
    """
    latest_event = last_reported_event
    current_datetime_mark = datetime.datetime.utcnow()
    current_time_mark = current_datetime_mark.isoformat() + 'Z'
    parsed_events = []

    # add 1 second to make sure we don't get the same event over and over)
    start_time = (last_reported_event + datetime.timedelta(seconds=1)).isoformat() + 'Z'

    alarms_list = []

    # check for Legacy event API.
    if LEGACY_EVENTS_API:
        events_query_tpl = {
            "severity": [],
            "query": {
                "type": "alarm",
            },
            "_offset": None,
            "summary": False,
        }
    else:
        events_query_tpl = {
            "severity": [],
            "query": {
                "type": [
                    "alarm"
                ]
            },
            "_offset": None,
            "view": {
                "summary": False
            }
        }

    # get events from last event.
    query = deepcopy(events_query_tpl)
    query["start_time"] = start_time
    query["end_time"] = current_time_mark

    # check for Legacy event API.
    if LEGACY_EVENTS_API:
        event_resp = sdk.post.events_query(query, api_version='v2.0')
    else:
        # if not legacy, use latest version.
        event_resp = sdk.post.events_query(query)

    status_alarm = event_resp.cgx_status
    raw_alarms = event_resp.cgx_content
    status_code = event_resp.status_code

    if not status_alarm or type(raw_alarms) is not dict:
        # error, return empty.
        # This response will trigger a relogin attempt to mitigate multi-token refresh scenarios.
        return False, last_reported_event, [], 0, status_code

    # iterate through paged queries as supported.

    # iterate through alarms
    if status_alarm:
        # add current alarms to list
        alarms_list.extend(raw_alarms.get('items', []))
        offset = raw_alarms.get('_offset')
        # debug offset
        # print str(raw_alarms.get("total_count", "??")) + " / " + str(len(alarms_list))
        while offset:
            query["_offset"] = offset
            event_resp = sdk.post.events_query(query)
            status_alarm = event_resp.cgx_status
            raw_alarms = event_resp.cgx_content
            status_code = event_resp.status_code

            if not status_alarm:
                # error, return empty.
                # This response will trigger a relogin attempt to mitigate multi-token refresh scenarios.
                return False, last_reported_event, [], 0, status_code

            alarms_list.extend(raw_alarms.get('items', []))
            offset = raw_alarms.get('_offset')
            # debug offset
            # print str(raw_alarms.get("total_count", "??")) + " / " + str(len(alarms_list))

    if not alarms_list:
        # Valid transaction, but no data. Return empty.
        return True, last_reported_event, [], 0, status_code

    # combine lists
    combined_list = []
    combined_list.extend(alarms_list)

    # sort by create time
    events_list = sorted(combined_list, key=lambda k: k["time"])

    # parse events
    for event in events_list:

        discard_event = False

        event_dict = collections.OrderedDict()

        event_type = event.get('type', '')

        # This is for Alert/Alarm processing.
        event_isodate = event.get('time')
        syslogdate = "NO_TIME_REPORTED"
        if event_isodate:
            # convert to datetime
            if len(event_isodate) > 20:  # quick check for microseconds.
                event_datetime = datetime.datetime.strptime(event_isodate, '%Y-%m-%dT%H:%M:%S.%fZ')
            else:
                event_datetime = datetime.datetime.strptime(event_isodate, '%Y-%m-%dT%H:%M:%SZ')

            syslogdate = event_datetime.strftime(SYSLOG_DATE_FORMAT)

            # if no latest event or event is newer, update.
            if not latest_event:
                # print "Updating '{0}' to '{1}'.".format(str(latest_event),
                #                                     event_datetime.strftime("%b %d %Y %H:%M:%S"))
                latest_event = event_datetime
            elif event_datetime > latest_event:
                # print "Updating '{0}' to '{1}'.".format(latest_event.strftime("%b %d %Y %H:%M:%S"),
                #                                     event_datetime.strftime("%b %d %Y %H:%M:%S"))
                latest_event = event_datetime

        info_string = ""
        for key, value in event.get('info', {}).iteritems():
            if type(value) is list:
                info_string = info_string + key.upper() + ": " + str(",".join(value)) + " "
            else:
                info_string = info_string + key.upper() + ": " + str(value) + " "
        # pull code and reference for filtering
        code = event.get('code', '')
        reference = event.get('entity_ref', "none")

        # find out if this Alarm event should be ignored.
        for regex_search in sdk_vars['ignore_alarm']:
            # if discard is already determined, bypass loop logic.
            if discard_event:
                continue

            # check code then reference for match
            code_check = regex_search.match(code)
            reference_check = regex_search.match(reference)

            if code_check:
                clilogger.debug("DISCARD: Alarm discarded due to code '{0}' matching '{1}'."
                                "".format(code, regex_search.pattern))
                discard_event = True
            elif reference_check:
                clilogger.debug("DISCARD: Alarm discarded due to reference '{0}' matching '{1}'."
                                "".format(reference, regex_search.pattern))
                discard_event = True
            else:
                clilogger.debug("KEEP: Alarm kept due to no match of code '{0}' or reference '{1}' to '{2}'"
                                .format(code, reference, regex_search.pattern))

        if not discard_event:
            reference_string = "REFERENCE: " + reference

            # start adding items to ordered dict
            # xlate siteid to name, if exists
            event_siteid = event.get('site_id', '')
            event_elementid = event.get('element_id', '')

            if sdk_vars.get('emit_json'):
                # try to translate to name - if no name return site id, or UNKNOWN if no ID in message.
                event_dict['site'] = id_map.get(event_siteid, event_siteid)

                # just populate the message as raw JSON.
                event_dict['info'] = json.dumps(event)

            elif RFC5424:
                # Strict RFC5424
                # set type to alert if not set.
                event_dict['type'] = event.get('type', 'alarm')

                event_dict['cloudgenix_host'] = id_map.get(event_elementid, event_elementid)

                # try to translate to name - if no name return site id, or UNKNOWN if no ID in message.
                event_dict['site'] = id_map.get(event_siteid, event_siteid)

                if not event.get('cleared'):
                    event_dict['status'] = 'raised'
                else:
                    event_dict['status'] = 'cleared'
                event_dict['code'] = code
                event_dict['device_time'] = syslogdate
                event_dict['severity'] = event.get('severity', 'info')
                event_dict['correlation'] = event.get('correlation_id', '')
                # for RFC5424, pass everything as key/value.
                event_dict.update(event.get('info', {}))

            else:
                # Normal text SYSLOG.

                # try to translate to name - if no name return site id, or UNKNOWN if no ID in message.
                event_dict['site'] = id_map.get(event_siteid, event_siteid)

                if not event.get('cleared'):
                    event_dict['status'] = 'raised'
                else:
                    event_dict['status'] = 'cleared'
                event_dict['code'] = code
                event_dict['device_time'] = syslogdate
                event_dict['severity'] = event.get('severity', 'info')
                event_dict['type'] = event.get('type', '')
                event_dict['correlation'] = event.get('correlation_id', '')
                event_dict['info'] = reference_string + " " + info_string

            parsed_events.append(event_dict)

    # print json.dumps(parsed_events, indent=4)
    #
    # print repr(latest_event)

    return True, latest_event, parsed_events, len(alarms_list), status_code


def update_parse_alert(last_reported_event, sdk_vars):
    """
    Get events from tenant.
    :param sdk_vars: sdk_vars global info struct
    :param last_reported_event: datetime.datetime of the oldest event reported.
    :return: status (boolean), parsed_events (event report struct), json_events (events list in json)
    """
    latest_event = last_reported_event
    current_datetime_mark = datetime.datetime.utcnow()
    current_time_mark = current_datetime_mark.isoformat() + 'Z'
    parsed_events = []

    # add 1 second to make sure we don't get the same event over and over)
    start_time = (last_reported_event + datetime.timedelta(seconds=1)).isoformat() + 'Z'

    alerts_list = []

    # check for Legacy event API.
    if LEGACY_EVENTS_API:
        events_query_tpl = {
            "severity": [],
            "query": {
                "type": "alert",
            },
            "_offset": None,
            "summary": False,
        }
    else:
        events_query_tpl = {
            "severity": [],
            "query": {
                "type": [
                    "alert"
                ]
            },
            "_offset": None,
            "view": {
                "summary": False
            }
        }

    # get events from last event.
    query = deepcopy(events_query_tpl)
    query["start_time"] = start_time
    query["end_time"] = current_time_mark

    # check for Legacy event API.
    if LEGACY_EVENTS_API:
        event_resp = sdk.post.events_query(query, api_version='v2.0')
    else:
        # if not legacy, use latest version.
        event_resp = sdk.post.events_query(query)

    status_alert = event_resp.cgx_status
    raw_alerts = event_resp.cgx_content
    status_code = event_resp.status_code

    if not status_alert or type(raw_alerts) is not dict:
        # error, return empty.
        # This response will trigger a relogin attempt to mitigate multi-token refresh scenarios.
        return False, last_reported_event, [], 0, status_code

    # iterate through paged queries as supported.

    # iterate through alerts
    if status_alert:
        # add current alerts to list
        alerts_list.extend(raw_alerts.get('items', []))
        offset = raw_alerts.get('_offset')
        # debug offset
        # print str(raw_alerts.get("total_count", "??")) + " / " + str(len(alarms_list))
        while offset:
            query["_offset"] = offset
            event_resp = sdk.post.events_query(query)
            status_alert = event_resp.cgx_status
            raw_alerts = event_resp.cgx_content
            status_code = event_resp.status_code

            if not status_alert:
                # error, return empty.
                # This response will trigger a relogin attempt to mitigate multi-token refresh scenarios.
                return False, last_reported_event, [], 0, status_code

            alerts_list.extend(raw_alerts.get('items', []))
            offset = raw_alerts.get('_offset')
            # debug offset
            # print str(raw_alerts.get("total_count", "??")) + " / " + str(len(alerts_list))

    if not alerts_list:
        # Valid transaction, but no data. Return empty.
        return True, last_reported_event, [], 0, status_code

    # combine lists
    combined_list = []
    combined_list.extend(alerts_list)

    # sort by create time
    events_list = sorted(combined_list, key=lambda k: k["time"])

    # parse events
    for event in events_list:

        discard_event = False
        # print "EVENT: ", json.dumps(event, indent=4)

        event_dict = collections.OrderedDict()

        event_type = event.get('type', '')

        # This is for Alert/Alarm processing.
        event_isodate = event.get('time')
        syslogdate = "NO_TIME_REPORTED"
        if event_isodate:
            # convert to datetime
            if len(event_isodate) > 20:  # quick check for microseconds.
                event_datetime = datetime.datetime.strptime(event_isodate, '%Y-%m-%dT%H:%M:%S.%fZ')
            else:
                event_datetime = datetime.datetime.strptime(event_isodate, '%Y-%m-%dT%H:%M:%SZ')

            syslogdate = event_datetime.strftime(SYSLOG_DATE_FORMAT)

            # if no latest event or event is newer, update.
            if not latest_event:
                # print "Updating '{0}' to '{1}'.".format(str(latest_event),
                #                                     event_datetime.strftime("%b %d %Y %H:%M:%S"))
                latest_event = event_datetime
            elif event_datetime > latest_event:
                # print "Updating '{0}' to '{1}'.".format(latest_event.strftime("%b %d %Y %H:%M:%S"),
                #                                     event_datetime.strftime("%b %d %Y %H:%M:%S"))
                latest_event = event_datetime

        info_string = ""
        for key, value in event.get('info', {}).iteritems():
            if type(value) is list:
                info_string = info_string + key.upper() + ": " + str(",".join(value)) + " "
            else:
                info_string = info_string + key.upper() + ": " + str(value) + " "

        # pull code and reference for filtering
        code = event.get('code', '')
        reference = event.get('entity_ref', "none")

        # find out if this Alert event should be ignored.
        for regex_search in sdk_vars['ignore_alert']:
            # if discard is already determined, bypass loop logic.
            if discard_event:
                continue

            # check code then reference for match
            code_check = regex_search.match(code)
            reference_check = regex_search.match(reference)

            if code_check:
                clilogger.debug("DISCARD: Alert discarded due to code '{0}' matching '{1}'."
                                "".format(code, regex_search.pattern))
                discard_event = True
            elif reference_check:
                clilogger.debug("DISCARD: Alert discarded due to reference '{0}' matching '{1}'."
                                "".format(reference, regex_search.pattern))
                discard_event = True
            else:
                clilogger.debug("KEEP: Alert kept due to no match of code '{0}' or reference '{1}' to '{2}'"
                                .format(code, reference, regex_search.pattern))

        if not discard_event:
            reference_string = "REFERENCE: " + reference

            # start adding items to ordered dict
            # xlate siteid to name, if exists
            event_siteid = event.get('site_id', '')
            event_elementid = event.get('element_id', '')
            # print "EVENT_SITEID,", event_siteid, json.dumps(event, indent=4)


            if sdk_vars.get('emit_json'):
                # try to translate to name - if no name return site id, or UNKNOWN if no ID in message.
                event_dict['site'] = id_map.get(event_siteid, event_siteid)

                # just populate the message as raw JSON.
                event_dict['info'] = json.dumps(event)

            elif RFC5424:
                # Strict RFC5424
                # set type to alert if not set.
                event_dict['type'] = event.get('type', 'alert')

                event_dict['cloudgenix_host'] = id_map.get(event_elementid, event_elementid)

                # try to translate to name - if no name return site id, or UNKNOWN if no ID in message.
                event_dict['site'] = id_map.get(event_siteid, event_siteid)

                # if not event.get('cleared'):
                #     event_dict['status'] = 'raised'
                # else:
                #     event_dict['status'] = 'cleared'
                event_dict['code'] = code
                event_dict['device_time'] = syslogdate
                event_dict['severity'] = event.get('severity', 'info')
                event_dict['correlation'] = event.get('correlation_id', '')
                # for RFC5424, pass everything as key/value.
                event_dict.update(event.get('info', {}))

            else:
                # Normal text SYSLOG.

                # try to translate to name - if no name return site id, or UNKNOWN if no ID in message.
                event_dict['site'] = id_map.get(event_siteid, event_siteid)

                # if not event.get('cleared'):
                #     event_dict['status'] = 'raised'
                # else:
                #     event_dict['status'] = 'cleared'
                event_dict['code'] = code
                event_dict['element'] = event.get('element_id', '')
                event_dict['device_time'] = syslogdate
                event_dict['severity'] = event.get('severity', 'info')
                event_dict['type'] = event.get('type', '')
                event_dict['correlation'] = event.get('correlation_id', '')
                event_dict['info'] = reference_string + " " + info_string

            parsed_events.append(event_dict)

    # print json.dumps(parsed_events, indent=4)
    #
    # print repr(latest_event)

    return True, latest_event, parsed_events, len(alerts_list), status_code


def emit_syslog(parsed_events, rmt_logger, passed_id_map=None):
    """
    Fire out the syslogs from the parsed_events.
    :param parsed_events:
    :return:
    """

    if not passed_id_map or type(passed_id_map) is not dict:
        id_name_map = {}
    else:
        id_name_map = passed_id_map

    # reverse list, oldest first
    parsed_events.reverse()

    # iterate the events!
    if RFC5424:
        # RFC 5424 compliant strings
        for event in parsed_events:
            log_string = "{0} {1} ".format(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT),
                                           RFC5424_HOSTNAME)
            # print "LOG_STRING", log_string
            # print json.dumps(event, indent=4)
            for key, value in event.iteritems():
                if key in ['type']:
                    # no label for element
                    log_string += str(value) + ": "
                elif key in ['info']:
                    log_string += str(value)
                else:
                    log_string += key.upper() + "=\"" + str(value).replace('"', '\\"') + "\" "

            if not sdk_vars['disable_name']:
                # remap IDs to names
                for key, value in id_name_map.iteritems():
                    log_string = log_string.replace(key, "{0} ({1})".format(value, key))

            clilogger.debug("LOG MESSAGE SIZE: ", len(log_string))
            # set the severity. If none, set to info.
            severity = str(event.get('severity', 'info')).lower()
            # TCP syslog needs a LF to segment entries.
            if EMIT_TCP_SYSLOG:
                log_string += "\n"

            if severity in ['info']:
                rmt_logger.info(log_string)
            elif severity in ['minor']:
                rmt_logger.warn(log_string)
            elif severity in ['major']:
                rmt_logger.error(log_string)
            elif severity in ['critical']:
                rmt_logger.critical(log_string)
    else:
        # old text strings.
        for event in parsed_events:
            log_string = ""
            for key, value in event.iteritems():
                if key in ['site', 'operator']:
                    # no label for these
                    log_string += str(value) + ": "
                elif key in ['info']:
                    log_string += str(value)
                else:
                    log_string += key.upper() + ": " + str(value) + " "

            if not sdk_vars['disable_name']:
                # remap IDs to names
                for key, value in id_name_map.iteritems():
                    log_string = log_string.replace(key, "{0} ({1})".format(value, key))

            clilogger.debug("LOG MESSAGE SIZE: ", len(log_string))
            # set the severity. If none, set to info.
            severity = str(event.get('severity', 'info')).lower()
            # TCP syslog needs a LF to segment entries.
            if EMIT_TCP_SYSLOG:
                log_string += "\n"

            if severity in ['info']:
                rmt_logger.info(log_string)
            elif severity in ['minor']:
                rmt_logger.warn(log_string)
            elif severity in ['major']:
                rmt_logger.error(log_string)
            elif severity in ['critical']:
                rmt_logger.critical(log_string)

    return


def local_event_generate(site="CG-SYSLOG-APIGW", status="raised", code="CG_API_SYSLOG_GW_GENERATED_ALARM",
                         device_time=datetime.datetime.utcnow(),
                         severity="info", notice_type="alert", correlation="NONE",
                         info=None, element=None, sdk_vars=None):
    """
    Send a syslog event for LOCAL CG API to SYSLOG gateway events.
    :param site: Site ID/Name
    :param status: string (raised|cleared)
    :param code: string
    :param device_time: String in strftime(SYSLOG_DATE_FORMAT) format. Default is now.
    :param severity: string (minor|major|critical) - only with alarm.
    :param notice_type: string (alert|alarm)
    :param correlation: string - ID to corralate other events
    :param info: dictionary of key/string value details
    :param element: Name of device (or controller if no device)
    :param sdk_vars: sdk_vars global info struct
    :return: no value
    """
    return_alert = collections.OrderedDict()

    if sdk_vars.get('emit_json'):
        # Return JSON format.

        if not info or type(info) is not dict:
            info = {
                "notice": "CG API to SYSLOG Generated Alert"
            }

        return_alert['site'] = site
        return_alert['info'] = {
            "info": info,
            "code": code,
            "severity": severity,
            "correlation_id": correlation,
            "time": device_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "cleared": False if status.lower() is "raised" else True,
            "type": notice_type,
        }

    elif RFC5424:
        # Strict RFC5424
        if not info or type(info) is not dict:
            info = {
                "notice": "CG API to SYSLOG Generated Alert"
            }

        return_alert['type'] = notice_type
        if not element:
            return_alert['cloudgenix_host'] = RFC5424_HOSTNAME
        else:
            return_alert['cloudgenix_host'] = element
        return_alert['site'] = site
        if notice_type.lower() in ['alarm']:
            return_alert["cleared"] = False if status.lower() is "raised" else True

        return_alert['code'] = code
        return_alert['severity'] = severity
        return_alert['correlation_id'] = correlation
        return_alert['time'] = device_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        return_alert.update(info)

    else:
        # Return text format.

        if not info or type(info) is not dict:
            info = {
                "notice": "CG API to SYSLOG Generated Alert"
            }
        info_string = ""
        for key, value in info.iteritems():
            if type(value) is list:
                info_string = info_string + key.upper() + ": " + str(",".join(value)) + " "
            else:
                info_string = info_string + key.upper() + ": " + str(value) + " "

        return_alert['site'] = site
        return_alert['status'] = status
        return_alert['element'] = element
        return_alert['device_time'] = device_time.strftime(SYSLOG_DATE_FORMAT)
        return_alert['severity'] = severity
        return_alert['type'] = notice_type
        return_alert['correlation'] = correlation
        return_alert['info'] = info_string

    emit_syslog([return_alert], remote_logger)

    return


if __name__ == "__main__":
    # Login first thing.
    # parse arguments
    parser = argparse.ArgumentParser(description="CloudGenix API -> SYSLOG Gateway v{}".format(SYSLOG_GW_VERSION))

    # Allow Controller modification and debug level sets.
    syslog_group = parser.add_argument_group('SYSLOG', 'These options set where to send SYSLOG messages')
    syslog_group.add_argument("--server", "-S", help="SYSLOG server. Required.", required=True,
                              default=None, )
    syslog_group.add_argument("--port", "-P", help="Port on SYSLOG server. "
                                                   "Default is 514.",
                              default=514, type=int)
    syslog_group.add_argument("--use-tcp", "-T", help="Send TCP Syslog instead of UDP.",
                              default=False, action='store_true')
    syslog_group.add_argument("--facility", "-F", help="SYSLOG Facility to use server. "
                                                       "Default is 'user'.",
                              default='user')
    syslog_group.add_argument("--date-format", help="Date formatting using 'strftime' style strings, "
                                                    "See http://strftime.org/ ."
                                                    "Default is '{0}'.".format(SYSLOG_DATE_FORMAT.replace('%', '%%')),
                              default=SYSLOG_DATE_FORMAT, type=str)
    syslog_group.add_argument("--rfc5424", help="RFC 5424 Compliant Syslog messages",
                              default=False, action='store_true')
    syslog_group.add_argument('--from-hostname', required='--rfc5424' in sys.argv,
                              type=str, help="From Hostname string, required if RFC 5424 log format.")

    parsing_group = parser.add_argument_group('Parsing', 'These options change how this program parses messages')
    parsing_group.add_argument("--emitjson", "-J", help="Emit messages as JSON",
                               action='store_true',
                               default=False)
    parsing_group.add_argument("--disable-name", "-DNAME", help="Disable translation of ID to Name.",
                               action='store_true',
                               default=False)
    parsing_group.add_argument("--enable-operator", "-EOPERATOR", help="Enable Sending Operator Log",
                               action='store_true',
                               default=False)
    parsing_group.add_argument("--enable-audit", "-EAUDIT", help="Enable Sending Audit Log",
                               action='store_true',
                               default=False)
    parsing_group.add_argument("--disable-alarm", "-DALARM", help="Disable Sending Alert Log",
                               action='store_true',
                               default=False)
    parsing_group.add_argument("--disable-alert", "-DALERT", help="Disable Sending Alert Log",
                               action='store_true',
                               default=False)
    parsing_group.add_argument("--legacy-events", "-LE", help="Use Legacy Events API (v2.0)",
                               action='store_true',
                               default=False)

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. https://controller.cloudgenix.com:8443",
                                  default=None)

    controller_group.add_argument("--hours", "-H", help="Number of Hours to go back in history on cold start (1-240)",
                                  type=int, default=DEFAULT_COLD_START_SEND_OLD_EVENTS)

    controller_group.add_argument("--delay", "-L", help="Number of seconds to wait between API refreshes (60-65535)",
                                  type=int, default=DEFAULT_TIME_BETWEEN_API_UPDATES)

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of cloudgenix_settings.py",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of cloudgenix_settings.py",
                             default=None)
    login_group.add_argument("--insecure", "-I", help="Do not verify SSL certificate",
                             action='store_true',
                             default=False)
    login_group.add_argument("--noregion", "-NR", help="Ignore Region-based redirection.",
                             dest='ignore_region', action='store_true', default=False)

    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    group = debug_group.add_mutually_exclusive_group()
    group.add_argument("--rest", "-R", help="Show REST requests",
                       action='store_true',
                       default=False)
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2",
                             default=0)

    args = vars(parser.parse_args())

    sdk_vars["debuglevel"] = int(args['debug'])

    # Build SDK Constructor
    if args['controller'] and args['insecure']:
        sdk = cloudgenix.API(controller=args['controller'], ssl_verify=False)
    elif args['controller']:
        sdk = cloudgenix.API(controller=args['controller'])
    elif args['insecure']:
        sdk = cloudgenix.API(ssl_verify=False)
    else:
        sdk = cloudgenix.API()

    # check for region ignore
    if args['ignore_region']:
        sdk.ignore_region = True

    if args['debug']:
        sdk.set_debug(int(args['debug']))

    # set API refresh delay to default or ARG supplied value.
    if args['delay'] <= 60:
        refresh_delay = 60
    elif args['delay'] > 65535:
        refresh_delay = 65535
    else:
        refresh_delay = args['delay']

    sdk_vars['operator_event_start'] = datetime.datetime.utcnow() - datetime.timedelta(hours=args['hours'])
    sdk_vars['audit_event_start'] = datetime.datetime.utcnow() - datetime.timedelta(hours=args['hours'])
    sdk_vars['alarm_event_start'] = datetime.datetime.utcnow() - datetime.timedelta(hours=args['hours'])
    sdk_vars['alert_event_start'] = datetime.datetime.utcnow() - datetime.timedelta(hours=args['hours'])
    sdk_vars['emit_json'] = args['emitjson']
    sdk_vars['disable_name'] = args['disable_name']
    sdk_vars['disable_alarm'] = args['disable_alarm']
    sdk_vars['disable_alert'] = args['disable_alert']
    # audit and operator should be disabled by default
    sdk_vars['disable_operator'] = not args['enable_operator']
    sdk_vars['disable_audit'] = not args['enable_audit']

    if args['facility'] not in ACCEPTABLE_FACILITY:
        print "ERROR: Facility given was {0}. Needs to be one of: \n\t{1}.".format(args['facility'],
                                                                                   ", ".join(ACCEPTABLE_FACILITY))
        exit(1)

    # set syslog stuffs
    SYSLOG_HOST = args['server']
    SYSLOG_PORT = args['port']
    SYSLOG_FACILITY = args['facility']

    # check for TCP Syslog
    if args['use_tcp']:
        EMIT_TCP_SYSLOG = True

    # Set date if modified.
    SYSLOG_DATE_FORMAT = args['date_format']

    if args['rfc5424']:
        RFC5424 = True
        RFC5424_HOSTNAME = args['from_hostname']

    # Start remote logger
    remote_logger = logging.getLogger("REMOTE")
    if EMIT_TCP_SYSLOG:
        syslog = SysLogHandler(address=(SYSLOG_HOST, SYSLOG_PORT),
                               facility=SYSLOG_FACILITY,
                               socktype=socket.SOCK_STREAM)
    else:
        syslog = SysLogHandler(address=(SYSLOG_HOST, SYSLOG_PORT),
                               facility=SYSLOG_FACILITY)

    remote_logger.addHandler(syslog)
    remote_logger.setLevel(logging.INFO)

    # set debug logger state
    if args['debug'] == 1:
        logging.basicConfig(level=logging.INFO)
        clilogger = logging.getLogger("debugger")
        clilogger.setLevel(logging.INFO)
    elif args['debug'] >= 2:
        logging.basicConfig(level=logging.DEBUG)
        clilogger = logging.getLogger("debugger")
        clilogger.setLevel(logging.DEBUG)
    else:
        # set logging off unless asked for, since we are using same library system for sending syslog.
        pass

    # set legacy V2 global
    LEGACY_EVENTS_API = args['legacy_events']

    clilogger.info("Initial Launch:")

    # Check config file
    try:
        from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

        sdk_vars["email"] = CLOUDGENIX_USER
        sdk_vars["password"] = CLOUDGENIX_PASSWORD
    except ImportError:
        print "{0} - Could not read cloudgenix_settings.py config file. Exiting.".format(
            str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)))
        local_event_generate(
            info={"NOTICE": "Could not read cloudgenix_settings.py config file. Exiting."},
            code="CG_API_SYSLOG_GW_CONFIG_READ_FAILURE",
            severity="critical",
            notice_type="alarm",
            sdk_vars=sdk_vars)
        sys.exit(1)

    # load ignore regular expressions
    try:
        from cloudgenix_settings import OPERATOR_EVENT_IGNORE
    except ImportError:
        OPERATOR_EVENT_IGNORE = []

    try:
        from cloudgenix_settings import AUDIT_EVENT_IGNORE
    except ImportError:
        AUDIT_EVENT_IGNORE = []

    try:
        from cloudgenix_settings import ALARM_EVENT_IGNORE
    except ImportError:
        ALARM_EVENT_IGNORE = []

    try:
        from cloudgenix_settings import ALERT_EVENT_IGNORE
    except ImportError:
        ALERT_EVENT_IGNORE = []

    operator_compile = []
    audit_compile = []
    alarm_compile = []
    alert_compile = []

    for regstr in OPERATOR_EVENT_IGNORE:
        operator_compile.append(re.compile(regstr))
    for regstr in AUDIT_EVENT_IGNORE:
        audit_compile.append(re.compile(regstr))
    for regstr in ALARM_EVENT_IGNORE:
        alarm_compile.append(re.compile(regstr))
    for regstr in ALERT_EVENT_IGNORE:
        alert_compile.append(re.compile(regstr))

    sdk_vars['ignore_audit'] = operator_compile
    sdk_vars['ignore_audit'] = audit_compile
    sdk_vars['ignore_alarm'] = alarm_compile
    sdk_vars['ignore_alert'] = alert_compile

    # Start syslog stuff
    # send cold start.
    local_event_generate(
        info={"NOTICE": "CG API to Syslog Service COLD START"},
        code="CG_API_SYSLOG_GW_COLD_START",
        sdk_vars=sdk_vars)

    print "CloudGenix API -> SYSLOG Gateway v{0} ({1})\n".format(SYSLOG_GW_VERSION,
                                                                 "{}, API v{}".format(str(sdk.controller),
                                                                                      cloudgenix.version))

    # interactive or cmd-line specified initial login
    logged_in = False
    while not logged_in:

        logged_in = sdk.interactive.login(email=sdk_vars['email'], password=sdk_vars['password'])

        if not logged_in:
            print "{0} - Initial login failed. Will Auto-retry in {1} seconds. Ctrl-C to stop.".format(
                str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)), TIME_BETWEEN_LOGIN_ATTEMPTS)
            local_event_generate(info={"NOTICE": "Initial login failed. Will Auto-retry in {0} seconds"
                                                 "".format(TIME_BETWEEN_LOGIN_ATTEMPTS)},
                                 code="CG_API_SYSLOG_GW_LOGIN_FAILURE",
                                 severity="critical",
                                 notice_type="alarm",
                                 sdk_vars=sdk_vars)
            time.sleep(TIME_BETWEEN_LOGIN_ATTEMPTS)
        else:
            print "{0} - Initial login successful." \
                  "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)))
            # update and wait!
            logintime = datetime.datetime.utcnow()

    if not sdk_vars['disable_name']:
        print "\nCaching ID->Name values for log message substitution.."
        id_map = generate_id_name_map(sdk)
        # clean up unknown '0' values
        id_map.pop('0')
    else:
        # need something for id_map to pass single translations
        id_map = {}

    # syslog code start
    print "\nStarting syslog emitter for {0} with a {1} sec refresh, sending to {2}:{3}. Ctrl-C to stop." \
          "".format(sdk.tenant_name, str(refresh_delay), str(SYSLOG_HOST), str(SYSLOG_PORT))

    if sdk_vars['emit_json']:
        print "Switching to JSON SYSLOG messages from command-line switch."

    clilogger.info("Beginning query of events for {0}.".format(sdk.tenant_name))

    # logintime is when user last logged in
    logintime = datetime.datetime.utcnow()

    # last event date from sdk_vars
    operator_last_event_date = sdk_vars['operator_event_start']
    audit_last_event_date = sdk_vars['audit_event_start']
    alarm_last_event_date = sdk_vars['alarm_event_start']
    alert_last_event_date = sdk_vars['alert_event_start']

    # catch keyboard interrupt
    try:
        # query loop.
        while True:
            # check if login needs refreshed
            curtime = datetime.datetime.utcnow()
            if curtime > (logintime + datetime.timedelta(hours=REFRESH_LOGIN_TOKEN_INTERVAL)) or logged_in is False:
                if logged_in:
                    print "{0} - {1} hours since last login. attempting to re-login.".format(
                        str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                        str(REFRESH_LOGIN_TOKEN_INTERVAL))
                else:
                    print "{0} - Not logged in. attempting to re-login.".format(
                        str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)))

                # logout to attempt to release session ID
                _ = sdk.interactive.logout()
                # ignore success or fail of logout, continue to log in again.
                logged_in = False
                # try to re-login
                while not logged_in:
                    logged_in = sdk.interactive.login(email=sdk_vars['email'], password=sdk_vars['password'])

                    if not logged_in:
                        print "{0} - Re-login failed. Will Auto-retry in {1} seconds." \
                              "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                                        TIME_BETWEEN_LOGIN_ATTEMPTS)
                        local_event_generate(info={"NOTICE": "Re-login failed. Will Auto-retry in {0} seconds."
                                                             "".format(TIME_BETWEEN_LOGIN_ATTEMPTS)},
                                             code="CG_API_SYSLOG_GW_LOGIN_FAILURE",
                                             sdk_vars=sdk_vars)
                        time.sleep(TIME_BETWEEN_LOGIN_ATTEMPTS)
                    else:
                        print "{0} - Re-login successful." \
                              "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)))
                        # update and wait!
                        logintime = datetime.datetime.utcnow()

                        if not sdk_vars['disable_name']:
                            # update id-> name maps
                            print "\nUpdating ID->Name values for log message substitution.."
                            id_map = generate_id_name_map(sdk)

            # get new events, if logged in.
            if logged_in:
                if not sdk_vars['disable_operator']:
                    # Operator events
                    operator_status, operator_last_event_date, \
                    operator_parsed_events, operator_event_count, \
                    operator_resp_code = update_parse_operator(operator_last_event_date, sdk_vars=sdk_vars)

                    # success and data returned
                    if operator_status and operator_parsed_events:
                        print "{0} - {1} OPERATOR event(s) retrieved. Sending SYSLOG. (Last event at {2})".format(
                            str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                            str(len(operator_parsed_events)),
                            operator_last_event_date.strftime(SYSLOG_DATE_FORMAT))

                        emit_syslog(operator_parsed_events, remote_logger, id_map)

                    # success but no events or empty response.
                    elif operator_status:
                        print "{0} - No reportable OPERATOR events retrieved. No SYSLOG to send. (Last event at {1})" \
                              "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                                        operator_last_event_date.strftime(SYSLOG_DATE_FORMAT))

                    # transaction error, trigger a re-login.
                    else:
                        # queue for relogin if "needs auth" code.
                        if operator_resp_code in [401, 403]:
                            logged_in = False
                        print "{0} - CloudGenix OPERATOR API request error ({1}). (Last event at {2})".format(
                            str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                            operator_resp_code,
                            operator_last_event_date.strftime(SYSLOG_DATE_FORMAT))
                        local_event_generate(info={"NOTICE": "CloudGenix OPERATOR API request error "
                                                             "({0}).".format(operator_resp_code)},
                                             code="CG_API_SYSLOG_GW_REQUEST_FAILURE",
                                             sdk_vars=sdk_vars)

                if not sdk_vars['disable_audit']:
                    # Audit events
                    audit_status, audit_last_event_date, \
                    audit_parsed_events, audit_event_count, \
                    audit_resp_code = update_parse_audit(audit_last_event_date, sdk_vars=sdk_vars)

                    # success and data returned
                    if audit_status and audit_parsed_events:
                        print "{0} - {1} AUDIT event(s) retrieved. Sending SYSLOG. (Last event at {2})".format(
                            str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                            str(len(audit_parsed_events)),
                            audit_last_event_date.strftime(SYSLOG_DATE_FORMAT))

                        emit_syslog(audit_parsed_events, remote_logger, id_map)

                    # success but no events or empty response.
                    elif audit_status:
                        print "{0} - No reportable AUDIT events retrieved. No SYSLOG to send. (Last event at {1})" \
                              "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                                        audit_last_event_date.strftime(SYSLOG_DATE_FORMAT))

                    # transaction error, trigger a re-login.
                    else:
                        # queue for relogin if "needs auth" code.
                        if audit_resp_code in [401, 403]:
                            logged_in = False
                        print "{0} - CloudGenix AUDIT API request error ({1}). (Last event at {2})".format(
                            str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                            audit_resp_code,
                            audit_last_event_date.strftime(SYSLOG_DATE_FORMAT))
                        local_event_generate(info={"NOTICE": "CloudGenix AUDIT API request error "
                                                             "({0}).".format(audit_resp_code)},
                                             code="CG_API_SYSLOG_GW_REQUEST_FAILURE",
                                             sdk_vars=sdk_vars)

                if not sdk_vars['disable_alarm']:
                    # Alarm events
                    alarm_status, alarm_last_event_date, \
                    alarm_parsed_events, alarm_event_count, \
                    alarm_resp_code = update_parse_alarm(alarm_last_event_date, sdk_vars=sdk_vars)

                    # success and data returned
                    if alarm_status and alarm_parsed_events:
                        print "{0} - {1} ALARM event(s) retrieved. Sending SYSLOG. (Last event at {2})".format(
                            str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                            str(len(alarm_parsed_events)),
                            alarm_last_event_date.strftime(SYSLOG_DATE_FORMAT))

                        emit_syslog(alarm_parsed_events, remote_logger, id_map)

                    # success but no events or empty response.
                    elif alarm_status:
                        print "{0} - No reportable ALARM events retrieved. No SYSLOG to send. (Last event at {1})" \
                              "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                                        alarm_last_event_date.strftime(SYSLOG_DATE_FORMAT))

                    # transaction error, trigger a re-login.
                    else:
                        # queue for relogin if "needs auth" code.
                        if alarm_resp_code in [401, 403]:
                            logged_in = False
                        print "{0} - CloudGenix ALARM API request error ({1}). (Last event at {2})".format(
                            str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                            alarm_resp_code,
                            alarm_last_event_date.strftime(SYSLOG_DATE_FORMAT))
                        local_event_generate(info={"NOTICE": "CloudGenix ALARM API request error "
                                                             "({0}).".format(alarm_resp_code)},
                                             code="CG_API_SYSLOG_GW_REQUEST_FAILURE",
                                             sdk_vars=sdk_vars)

                if not sdk_vars['disable_alert']:
                    # Alert events
                    alert_status, alert_last_event_date, \
                    alert_parsed_events, alert_event_count, \
                    alert_resp_code = update_parse_alert(alert_last_event_date, sdk_vars=sdk_vars)

                    # success and data returned
                    if alert_status and alert_parsed_events:
                        print "{0} - {1} ALERT event(s) retrieved. Sending SYSLOG. (Last event at {2})".format(
                            str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                            str(len(alert_parsed_events)),
                            alert_last_event_date.strftime(SYSLOG_DATE_FORMAT))

                        emit_syslog(alert_parsed_events, remote_logger, id_map)

                    # success but no events or empty response.
                    elif alert_status:
                        print "{0} - No reportable ALERT events retrieved. No SYSLOG to send. (Last event at {1})" \
                              "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                                        alert_last_event_date.strftime(SYSLOG_DATE_FORMAT))

                    # transaction error, trigger a re-login.
                    else:
                        # queue for relogin if "needs auth" code.
                        if alert_resp_code in [401, 403]:
                            logged_in = False
                        print "{0} - CloudGenix ALERT API request error ({1}). (Last event at {2})".format(
                            str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                            alert_resp_code,
                            alert_last_event_date.strftime(SYSLOG_DATE_FORMAT))
                        local_event_generate(info={"NOTICE": "CloudGenix ALERT API request error "
                                                             "({0}).".format(alert_resp_code)},
                                             code="CG_API_SYSLOG_GW_REQUEST_FAILURE",
                                             sdk_vars=sdk_vars)

            # Not logged in
            else:
                print "{0} - Could not get events, not currently logged in.".format(
                    str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)))
                local_event_generate(info={"NOTICE": "Could not get events, not currently logged in."},
                                     code="CG_API_SYSLOG_GW_LOGIN_FAILURE",
                                     severity="critical",
                                     notice_type="alarm",
                                     sdk_vars=sdk_vars)

            # sleep for next update
            time.sleep(refresh_delay)
    except KeyboardInterrupt:
        local_event_generate(
            info={"NOTICE": "CG API to Syslog Service COLD STOP"},
            code="CG_API_SYSLOG_GW_COLD_STOP",
            sdk_vars=sdk_vars)
        print "Finished! exiting.."
        sdk.interactive.logout()
