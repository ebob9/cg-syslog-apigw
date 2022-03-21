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
    sys.stderr.write("ERROR: 'cloudgenix' python module required. (try 'pip install cloudgenix').\n {}\n".format(e))
    sys.exit(1)

# IDname for CloudGenix
try:
    from cloudgenix_idname import generate_id_name_map
except ImportError as e:
    sys.stderr.write("ERROR: 'cloudgenix-idnane' python module required. "
                     "(try 'pip install cloudgenix-idname').\n {}\m".format(e))
    sys.exit(1)

# Global Vars
ACCEPTABLE_FACILITY = ['auth', 'authpriv', 'cron', 'daemon', 'ftp', 'kern', 'lpr', 'mail', 'news', 'syslog',
                       'user', 'uucp', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7']
DEFAULT_TIME_BETWEEN_API_UPDATES = 300  # seconds
DEFAULT_COLD_START_SEND_OLD_EVENTS = 24  # hours
TIME_BETWEEN_LOGIN_ATTEMPTS = 300  # seconds
TIME_BETWEEN_IDNAME_REFRESH = 48 # hours
REFRESH_LOGIN_TOKEN_INTERVAL = 7  # hours

SYSLOG_GW_VERSION = "1.2.4"
EMIT_TCP_SYSLOG = False
SYSLOG_DATE_FORMAT = '%b %d %H:%M:%S'
RFC5424 = False
RFC5424_HOSTNAME = "cg-syslog-apigw"
LEGACY_EVENTS_API = False

# datetime Epoch for UNIX timestamp calcs
EPOCH = datetime.datetime(1970, 1, 1)

# Set NON-SYSLOG logging to use function name
clilogger = logging.getLogger(__name__)

# Generic structure to keep authentication info
sdk_vars = {
    "email": None,  # User Email
    "password": None,  # User password
    "auth_token": None,  # Static AUTH_TOKEN
    "selected_element_id": None,  # Selected Element ID
    "selected_site_id": None,  # Selected Site ID
    "emit_json": None,  # Emit syslog as JSON instead of text.
    "audit_event_start": datetime.datetime.utcnow() - datetime.timedelta(hours=24),  # this gets updated by arg vars.
    "alarm_event_start": datetime.datetime.utcnow() - datetime.timedelta(hours=24),  # this gets updated by arg vars.
    "alert_event_start": datetime.datetime.utcnow() - datetime.timedelta(hours=24),  # this gets updated by arg vars.
    "disable_name": False,  # Disable name parsing, this gets updated by arg vars
    "disable_audit": False,  # Disable audit event parsing, this gets updated by arg vars
    "disable_alert": False,  # Disable alert event parsing, this gets updated by arg vars
    "disable_alarm": False,  # Disable alarm parsing, this gets updated by arg vars
    "ignore_audit": [],  # Ignore list for Audits, loaded from cloudgenix_settings.py
    "ignore_alarm": [],  # Ignore list for Alarm, loaded from cloudgenix_settings.py
    "ignore_alert": []  # Ignore list for Alert, loaded from cloudgenix_settings.py
}

def _uppercase(obj):
    """ Make dictionary uppercase """
    if isinstance(obj, dict):
        return {k.upper():_uppercase(v) for k, v in obj.items()}
    elif isinstance(obj, (list, set, tuple)):
        t = type(obj)
        return t(_uppercase(o) for o in obj)
    elif isinstance(obj, str):
        return obj.upper()
    else:
        return obj


def clean_info(obj):
    datastr = json.dumps(obj)
    datastr = datastr.replace("{", "")
    datastr = datastr.replace("}", "")
    datastr = datastr.replace("[", "")
    datastr = datastr.replace("]", "")
    datastr = datastr.replace("\"", "")

    return datastr



def update_parse_audit(last_reported_event, sdk_vars):
    """
    Get audit from tenant.
    :param sdk_vars: sdk_vars global info struct
    :param last_reported_event: datetime.datetime of the oldest event reported.
    :return: status (boolean), parsed_events (event report struct), json_events (events list in json)
    """
    latest_event = last_reported_event
    current_datetime_mark = datetime.datetime.utcnow()
    # Access log requires EPOCH timestamp in ms
    current_time_mark = (current_datetime_mark - EPOCH).total_seconds() * 1000
    parsed_events = []

    # add 1 second to make sure we don't get the same event over and over)
    start_time = ((last_reported_event + datetime.timedelta(seconds=1)) - EPOCH).total_seconds() * 1000

    audit_query_tpl = {
        "limit": "100",
        "query_params": {
            "request_ts": {
                "gte": 152000000000
            },
            "response_ts": {
                "lte": 1525722908000
            }
        },
        "sort_params": {
            "response_ts": "desc"
        },
        "dest_page": 1
    }

    # get Audits from last event.
    query = deepcopy(audit_query_tpl)
    query["query_params"]["request_ts"]["gte"] = start_time
    query["query_params"]["response_ts"]["lte"] = current_time_mark

    audit_list = []

    # get events from last event.
    audit_resp = sdk.post.query_auditlog(query)
    status_audit = audit_resp.cgx_status
    raw_audit = audit_resp.cgx_content
    status_code = audit_resp.status_code

    if not status_audit or type(raw_audit) is not dict:
        # error, return empty.
        # This response will trigger a relogin attempt to mitigate multi-token refresh scenarios.
        return False, last_reported_event, [], 0, status_code

    #
    # Flag to track data
    #
    more_data = True

    # iterate through audits
    if status_audit:

        raw_audit_items = []

        cur_audit_items = raw_audit.get('items', [])

        if cur_audit_items:
            raw_audit_items.extend(cur_audit_items)

        # iterate until no more audit events
        while more_data:
            # increment dest_page in query
            query["dest_page"] += 1
            audit_resp = sdk.post.query_auditlog(query)
            status_audit = audit_resp.cgx_status
            raw_audit = audit_resp.cgx_content
            status_code = audit_resp.status_code

            if not status_audit:
                # error, return empty.
                # This response will trigger a relogin attempt to mitigate multi-token refresh scenarios.
                more_data = False

                #
                # Return already collected audit logs
                # return False, last_reported_event, [], 0, status_code
                #

            cur_audit_items = raw_audit.get('items', [])
            if cur_audit_items is None:
                more_data = False
            else:
                raw_audit_items.extend(cur_audit_items)

            # debug
            # sys.stdout.write(str(raw_audit.get("total_count", "??")) + " / " + str(len(raw_audit_items)) + "\n")

        parsed_audit_items = []

        # manipulate the log into a standard event format
        for iter_d in raw_audit_items:
            # deepcopy to allow modification
            d = deepcopy(iter_d)
            # remove '_' prefixed keys in audits.
            for k in iter_d.keys():
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

            # sys.stdout.write("AUDIT_REQUEST_DATETIME: {}\n".format(audit_request_datetime.isoformat() + 'Z'))
            # sys.stdout.write("LAST_REPORTED_EVENT:  {}\n".format(last_reported_event.isoformat() + 'Z'))
            # sys.stdout.write(" > {}\n".format((audit_request_datetime > last_reported_event)))

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
                # sys.stdout.write("Updating '{0}' to '{1}'.\n".format(str(latest_event)))
                #                                     event_datetime.strftime("%b %d %Y %H:%M:%S"))
                latest_event = event_datetime
            elif event_datetime > latest_event:
                # sys.stdout.write("Updating '{0}' to '{1}'.\n".format(latest_event.strftime("%b %d %Y %H:%M:%S")))
                #                                     event_datetime.strftime("%b %d %Y %H:%M:%S"))
                latest_event = event_datetime

        info_string = ""
        info_iter = event.get('info', {})
        # if info_iter happens to return 'None', continue with blank string.
        if info_iter is not None:
            info_upper = _uppercase(info_iter)
            info_string = clean_info(info_upper)

            # for key, value in event.get('info', {}).items():
            #     if type(value) is list:
            #         info_string = info_string + key.upper() + ": " + str(",".join(value)) + " "
            #     else:
            #         info_string = info_string + key.upper() + ": " + str(value) + " "

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

            event_dict['id'] = event_id
            parsed_events.append(event_dict)

    # sys.stdout.write(json.dumps(parsed_events, indent=4))
    #
    # sys.stdout.write(repr(latest_event))

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
        # sys.stdout.write(str(raw_alarms.get("total_count", "??")) + " / " + str(len(alarms_list)))
        while offset:
            query["_offset"] = offset
            event_resp = sdk.post.events_query(query)
            status_alarm = event_resp.cgx_status
            raw_alarms = event_resp.cgx_content
            status_code = event_resp.status_code

            if not status_alarm:
                # error, return empty.
                # This response will trigger a relogin attempt to mitigate multi-token refresh scenarios.
                # return False, last_reported_event, [], 0, status_code
                # Update: Do not return empty. Instead, return data already retrieved
                offset = None

            else:
                alarms_list.extend(raw_alarms.get('items', []))
                offset = raw_alarms.get('_offset')
            # debug offset
            # sys.stdout.write(str(raw_alarms.get("total_count", "??")) + " / " + str(len(alarms_list)))

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
                # sys.stdout.write("Updating '{0}' to '{1}'.\n".format(str(latest_event)))
                #                                     event_datetime.strftime("%b %d %Y %H:%M:%S"))
                latest_event = event_datetime
            elif event_datetime > latest_event:
                # sys.stdout.write("Updating '{0}' to '{1}'.\n".format(latest_event.strftime("%b %d %Y %H:%M:%S")))
                #                                     event_datetime.strftime("%b %d %Y %H:%M:%S"))
                latest_event = event_datetime

        info_string = ""
        info_iter = event.get('info', {})
        # if info_iter happens to return 'None', continue with blank string.
        if info_iter is not None:
            for key, value in event.get('info', {}).items():
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
                event_info = event.get('info', {})
                if event_info:
                    event_dict.update(event_info)

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

            event_dict['id'] = event.get('id','')
            parsed_events.append(event_dict)

    # sys.stdout.write(json.dumps(parsed_events, indent=4))
    #
    # sys.stdout.write(repr(latest_event))

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
        # sys.stdout.write(str(raw_alerts.get("total_count", "??")) + " / " + str(len(alarms_list)))
        while offset:
            query["_offset"] = offset
            event_resp = sdk.post.events_query(query)
            status_alert = event_resp.cgx_status
            raw_alerts = event_resp.cgx_content
            status_code = event_resp.status_code

            if not status_alert:
                # error, return empty.
                # This response will trigger a relogin attempt to mitigate multi-token refresh scenarios.
                # return False, last_reported_event, [], 0, status_code
                # Update: Do not return empty. Instead, return data already retrieved
                offset = None
            else:
                alerts_list.extend(raw_alerts.get('items', []))
                offset = raw_alerts.get('_offset')
            # debug offset
            # sys.stdout.write(str(raw_alerts.get("total_count", "??")) + " / " + str(len(alerts_list)))

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
        # sys.stdout.write("EVENT: {}\n".format(json.dumps(event, indent=4)))

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
                # sys.stdout.write("Updating '{0}' to '{1}'\n.".format(str(latest_event)))
                #                                     event_datetime.strftime("%b %d %Y %H:%M:%S"))
                latest_event = event_datetime
            elif event_datetime > latest_event:
                # sys.stdout.write("Updating '{0}' to '{1}'\n.".format(latest_event.strftime("%b %d %Y %H:%M:%S")))
                #                                     event_datetime.strftime("%b %d %Y %H:%M:%S"))
                latest_event = event_datetime

        info_string = ""
        info_iter = event.get('info', {})
        if info_iter is None:
            info_string = ""
        else:
            for key, value in event.get('info', {}).items():
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
            # sys.stdout.write("EVENT_SITEID: {}\n".format(event_siteid, json.dumps(event, indent=4)))

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
                event_info = event.get('info', {})
                if event_info:
                    event_dict.update(event_info)

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

            event_dict['id'] = event.get('id','')
            parsed_events.append(event_dict)

    # sys.stdout.write(json.dumps(parsed_events, indent=4))
    #
    # sys.stdout.write(repr(latest_event))

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
            # sys.stdout.write("LOG_STRING: {}\n".format(log_string))
            # sys.stdout.write(json.dumps(event, indent=4))
            for key, value in event.items():
                if key in ['type']:
                    # no label for element
                    log_string += str(value) + ": "
                elif key in ['info']:
                    log_string += str(value)
                else:
                    log_string += key.upper() + "=\"" + str(value).replace('"', '\\"') + "\" "

            if not sdk_vars['disable_name']:
                # remap IDs to names
                for key, value in id_name_map.items():
                    log_string = log_string.replace(key, "{0} ({1})".format(value, key))

            # clilogger.debug("LOG MESSAGE SIZE: ", len(log_string))
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
            for key, value in event.items():
                if key in ['site', 'operator']:
                    # no label for these
                    log_string += str(value) + ": "
                elif key in ['info']:
                    log_string += str(value)
                else:
                    log_string += key.upper() + ": " + str(value) + " "

            if not sdk_vars['disable_name']:
                # remap IDs to names
                for key, value in id_name_map.items():
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
        for key, value in info.items():
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
    syslog_group.add_argument("--server", "-S", help="SYSLOG server. More than one can be specified separated by a comma.", required=True,
                              default=None, )
    syslog_group.add_argument("--port", "-P", help="Port on SYSLOG server. For multiple servers, their respective ports should be specified sequentially, separated by a comma."
                                                   "Default is 514.",
                              default=514, type=int)
    syslog_group.add_argument("--use-tcp", "-T", help="Send TCP Syslog instead of UDP. For multiple servers, their respective connection type should be specified sequentially, separated by a comma.",
                              default=False, action='store_true')
    syslog_group.add_argument("--facility", "-F", help="SYSLOG Facility to use server. "
                                                       "Default is 'user'.",
                              default='user')
    syslog_group.add_argument("--date-format", help="Date formatting using 'strftime' style strings, "
                                                    "See http://strftime.org/ ."
                                                    "Default is '{0}'.".format(SYSLOG_DATE_FORMAT.replace('%', '%%')),
                              default=SYSLOG_DATE_FORMAT, type=str)
    syslog_group.add_argument("--rfc5424", help="(Deprecated - now default) RFC 5424 Compliant Syslog messages",
                              default=True, action='store_true')
    syslog_group.add_argument('--from-hostname', required=False,
                              type=str, help="Specify Hostname string. "
                                             "If not set, will attempt to auto-detect hostname.",
                              default=None)

    parsing_group = parser.add_argument_group('Parsing', 'These options change how this program parses messages')
    parsing_group.add_argument("--emitjson", "-J", help="Emit messages as JSON",
                               action='store_true',
                               default=False)
    parsing_group.add_argument("--disable-name", "-DNAME", help="Disable translation of ID to Name.",
                               action='store_true',
                               default=False)
    parsing_group.add_argument("--enable-operator", "-EOPERATOR", help="(Deprecated - now part of Audit log. This "
                                                                       "switch remains for backwards compatibility.)",
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

    controller_group.add_argument("--hours", "-H", help="Number of Hours to go back in history on cold start (0-240)",
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
                             type=int, default=0)

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

    sdk_vars['audit_event_start'] = datetime.datetime.utcnow() - datetime.timedelta(hours=args['hours'])
    sdk_vars['alarm_event_start'] = datetime.datetime.utcnow() - datetime.timedelta(hours=args['hours'])
    sdk_vars['alert_event_start'] = datetime.datetime.utcnow() - datetime.timedelta(hours=args['hours'])
    sdk_vars['emit_json'] = args['emitjson']
    sdk_vars['disable_name'] = args['disable_name']
    sdk_vars['disable_alarm'] = args['disable_alarm']
    sdk_vars['disable_alert'] = args['disable_alert']
    # audit should be disabled by default
    sdk_vars['disable_audit'] = not args['enable_audit']

    if args['facility'] not in ACCEPTABLE_FACILITY:
        sys.stderr.write("ERROR: Facility given was {0}. "
                         "Needs to be one of: \n\t{1}.".format(args['facility'],
                                                               ", ".join(ACCEPTABLE_FACILITY)))
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

    # always RFC-5424. TODO: remove non-RFC 5424 output completely.
    RFC5424 = True
    # set hostname from args if specified, or get via socket lib.
    RFC5424_HOSTNAME = args['from_hostname'] if args['from_hostname'] else socket.gethostname()

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
        from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

        sdk_vars["auth_token"] = CLOUDGENIX_AUTH_TOKEN
    except ImportError:
        # will get caught below.
        CLOUDGENIX_AUTH_TOKEN = None

    try:
        from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

        sdk_vars["email"] = CLOUDGENIX_USER
        sdk_vars["password"] = CLOUDGENIX_PASSWORD
    except ImportError:
        CLOUDGENIX_USER = None
        CLOUDGENIX_PASSWORD = None
        # will get caught below

    # Validate we got an Auth Token or User/Pass
    if not (sdk_vars["email"] and sdk_vars["password"]) and not sdk_vars["auth_token"]:
        sys.stderr.write("{0} - Could not read user/pass or auth_token from cloudgenix_settings.py config file. "
                         "Exiting.\n".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT))))
        print("{0} {1} {2}".format(CLOUDGENIX_USER,
                                   CLOUDGENIX_PASSWORD,
                                   CLOUDGENIX_AUTH_TOKEN))
        sys.stderr.flush()
        local_event_generate(
            info={"NOTICE": "Could not read cloudgenix_settings.py config file. Exiting."},
            code="CG_API_SYSLOG_GW_CONFIG_READ_FAILURE",
            severity="critical",
            notice_type="alarm",
            sdk_vars=sdk_vars)
        sys.exit(1)

    # load ignore regular expressions
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

    audit_compile = []
    alarm_compile = []
    alert_compile = []

    for regstr in AUDIT_EVENT_IGNORE:
        audit_compile.append(re.compile(regstr))
    for regstr in ALARM_EVENT_IGNORE:
        alarm_compile.append(re.compile(regstr))
    for regstr in ALERT_EVENT_IGNORE:
        alert_compile.append(re.compile(regstr))

    sdk_vars['ignore_audit'] = audit_compile
    sdk_vars['ignore_alarm'] = alarm_compile
    sdk_vars['ignore_alert'] = alert_compile

    # Start syslog stuff
    # send cold start.
    local_event_generate(
        info={"NOTICE": "CG API to Syslog Service COLD START"},
        code="CG_API_SYSLOG_GW_COLD_START",
        sdk_vars=sdk_vars)

    sys.stdout.write("CloudGenix API -> SYSLOG Gateway v{0} ({1})\n".format(SYSLOG_GW_VERSION,
                                                                            "{}, API v{}".format(str(sdk.controller),
                                                                                                 cloudgenix.version)))
    sys.stdout.flush()

    # interactive or cmd-line specified initial login
    logged_in = False

    if sdk_vars["auth_token"]:
        # use Static AUTH_TOKEN based authentication.
        logged_in = sdk.interactive.use_token(sdk_vars["auth_token"])
        if not logged_in:
            # Token is not recoverable, exit.
            sys.stdout.write("{0} - Auth_Token use failed. Unrecoverable, please verify token.\n".format(
                str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT))))
            sys.stdout.flush()
            local_event_generate(info={"NOTICE": "Initial Auth_Token failed. Unrecoverable, will exit."
                                                 "".format(TIME_BETWEEN_LOGIN_ATTEMPTS)},
                                 code="CG_API_SYSLOG_GW_LOGIN_FAILURE",
                                 severity="critical",
                                 notice_type="alarm",
                                 sdk_vars=sdk_vars)
            sys.exit(1)
        else:
            sys.stdout.write("{0} - Initial Auth_Token use successful.\n"
                             "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT))))
            sys.stdout.flush()
            # update timestamp.
            logintime = datetime.datetime.utcnow()
    else:
        # Use email/password auth.
        while not logged_in:

            logged_in = sdk.interactive.login(email=sdk_vars['email'], password=sdk_vars['password'])

            if not logged_in:
                sys.stdout.write("{0} - Initial login failed. Will Auto-retry in {1} seconds. Ctrl-C to stop.\n".format(
                    str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)), TIME_BETWEEN_LOGIN_ATTEMPTS))
                sys.stdout.flush()
                local_event_generate(info={"NOTICE": "Initial login failed. Will Auto-retry in {0} seconds"
                                                     "".format(TIME_BETWEEN_LOGIN_ATTEMPTS)},
                                     code="CG_API_SYSLOG_GW_LOGIN_FAILURE",
                                     severity="critical",
                                     notice_type="alarm",
                                     sdk_vars=sdk_vars)
                time.sleep(TIME_BETWEEN_LOGIN_ATTEMPTS)
            else:
                sys.stdout.write("{0} - Initial login successful.\n"
                                 "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT))))
                sys.stdout.flush()
                # update and wait!
                logintime = datetime.datetime.utcnow()

    if not sdk_vars['disable_name']:
        sys.stdout.write("\nCaching ID->Name values for log message substitution..\n")
        id_map = generate_id_name_map(sdk)
        # clean up unknown '0' values
        id_map.pop('0')
    else:
        # need something for id_map to pass single translations
        id_map = {}

    # syslog code start
    sys.stdout.write("\nStarting syslog emitter for {0} with a {1} sec refresh, sending to {2}:{3}. Ctrl-C to stop.\n"
                     "".format(sdk.tenant_name, str(refresh_delay), str(SYSLOG_HOST), str(SYSLOG_PORT)))

    if sdk_vars['emit_json']:
        sys.stdout.write("Switching to JSON SYSLOG messages from command-line switch.\n")
    sys.stdout.flush()

    clilogger.info("Beginning query of events for {0}.".format(sdk.tenant_name))

    # logintime is when user last logged in
    logintime = datetime.datetime.utcnow()

    # last event date from sdk_vars
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
                if sdk_vars["email"]:
                    # email/password, normal session management
                    if logged_in:
                        sys.stdout.write("{0} - {1} hours since last login. attempting to re-login.\n".format(
                            str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                            str(REFRESH_LOGIN_TOKEN_INTERVAL)))

                    else:
                        sys.stdout.write("{0} - Not logged in. attempting to re-login.\n".format(
                            str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT))))
                    sys.stdout.flush()

                    # logout to attempt to release session ID
                    _ = sdk.interactive.logout()
                    # ignore success or fail of logout, continue to log in again.
                    logged_in = False
                    # try to re-login
                    while not logged_in:
                        logged_in = sdk.interactive.login(email=sdk_vars['email'], password=sdk_vars['password'])

                        if not logged_in:
                            sys.stdout.write("{0} - Re-login failed. Will Auto-retry in {1} seconds.\n"
                                             "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                                                       TIME_BETWEEN_LOGIN_ATTEMPTS))
                            local_event_generate(info={"NOTICE": "Re-login failed. Will Auto-retry in {0} seconds."
                                                                 "".format(TIME_BETWEEN_LOGIN_ATTEMPTS)},
                                                 code="CG_API_SYSLOG_GW_LOGIN_FAILURE",
                                                 sdk_vars=sdk_vars)
                            time.sleep(TIME_BETWEEN_LOGIN_ATTEMPTS)
                        else:
                            sys.stdout.write("{0} - Re-login successful.\n"
                                             "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT))))
                            # update and wait!
                            logintime = datetime.datetime.utcnow()

                        sys.stdout.flush()

            if curtime > (logintime + datetime.timedelta(hours=TIME_BETWEEN_IDNAME_REFRESH)):
                if not args['disable-name']:
                    sys.stdout.write("\nUpdating ID->Name values for log message substitution..\n")
                    id_map = generate_id_name_map(sdk)
                    id_map.pop('0')
                    sys.stdout.flush()

            # get new events, if logged in.
            if logged_in:
                if not sdk_vars['disable_audit']:
                    # Audit events
                    audit_status, audit_last_event_date, \
                        audit_parsed_events, audit_event_count, \
                        audit_resp_code = update_parse_audit(audit_last_event_date, sdk_vars=sdk_vars)

                    # success and data returned
                    if audit_status and audit_parsed_events:
                        sys.stdout.write("{0} - {1} AUDIT event(s) retrieved. Sending SYSLOG. "
                                         "(Last event at {2})\n"
                                         "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                                                   str(len(audit_parsed_events)),
                                                   audit_last_event_date.strftime(SYSLOG_DATE_FORMAT)))

                        emit_syslog(audit_parsed_events, remote_logger, id_map)

                    # success but no events or empty response.
                    elif audit_status:
                        sys.stdout.write("{0} - No reportable AUDIT events retrieved. No SYSLOG to send. "
                                         "(Last event at {1})\n"
                                         "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                                                   audit_last_event_date.strftime(SYSLOG_DATE_FORMAT)))

                    # transaction error, trigger a re-login.
                    else:
                        # queue for relogin if "needs auth" code.
                        if audit_resp_code in [401, 403] and not sdk_vars["auth_token"]:
                            logged_in = False
                        sys.stdout.write("{0} - CloudGenix AUDIT API request error ({1}). "
                                         "(Last event at {2})\n"
                                         "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                                                   audit_resp_code,
                                                   audit_last_event_date.strftime(SYSLOG_DATE_FORMAT)))
                        local_event_generate(info={"NOTICE": "CloudGenix AUDIT API request error "
                                                             "({0}).".format(audit_resp_code)},
                                             code="CG_API_SYSLOG_GW_REQUEST_FAILURE",
                                             sdk_vars=sdk_vars)
                    sys.stdout.flush()

                if not sdk_vars['disable_alarm']:
                    # Alarm events
                    alarm_status, alarm_last_event_date, \
                        alarm_parsed_events, alarm_event_count, \
                        alarm_resp_code = update_parse_alarm(alarm_last_event_date, sdk_vars=sdk_vars)

                    # success and data returned
                    if alarm_status and alarm_parsed_events:
                        sys.stdout.write("{0} - {1} ALARM event(s) retrieved. Sending SYSLOG. "
                                         "(Last event at {2})\n"
                                         "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                                                   str(len(alarm_parsed_events)),
                                                   alarm_last_event_date.strftime(SYSLOG_DATE_FORMAT)))

                        emit_syslog(alarm_parsed_events, remote_logger, id_map)

                    # success but no events or empty response.
                    elif alarm_status:
                        sys.stdout.write("{0} - No reportable ALARM events retrieved. No SYSLOG to send. "
                                         "(Last event at {1})\n"
                                         "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                                                   alarm_last_event_date.strftime(SYSLOG_DATE_FORMAT)))

                    # transaction error, trigger a re-login.
                    else:
                        # queue for relogin if "needs auth" code.
                        if alarm_resp_code in [401, 403] and not sdk_vars["auth_token"]:
                            logged_in = False
                        sys.stdout.write("{0} - CloudGenix ALARM API request error ({1}). "
                                         "(Last event at {2})\n"
                                         "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                                                   alarm_resp_code,
                                                   alarm_last_event_date.strftime(SYSLOG_DATE_FORMAT)))
                        local_event_generate(info={"NOTICE": "CloudGenix ALARM API request error "
                                                             "({0}).".format(alarm_resp_code)},
                                             code="CG_API_SYSLOG_GW_REQUEST_FAILURE",
                                             sdk_vars=sdk_vars)
                    sys.stdout.flush()

                if not sdk_vars['disable_alert']:
                    # Alert events
                    alert_status, alert_last_event_date, \
                        alert_parsed_events, alert_event_count, \
                        alert_resp_code = update_parse_alert(alert_last_event_date, sdk_vars=sdk_vars)

                    # success and data returned
                    if alert_status and alert_parsed_events:
                        sys.stdout.write("{0} - {1} ALERT event(s) retrieved. Sending SYSLOG. "
                                         "(Last event at {2})\n"
                                         "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                                                   str(len(alert_parsed_events)),
                                                   alert_last_event_date.strftime(SYSLOG_DATE_FORMAT)))

                        emit_syslog(alert_parsed_events, remote_logger, id_map)

                    # success but no events or empty response.
                    elif alert_status:
                        sys.stdout.write("{0} - No reportable ALERT events retrieved. No SYSLOG to send. "
                                         "(Last event at {1})\n"
                                         "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                                                   alert_last_event_date.strftime(SYSLOG_DATE_FORMAT)))

                    # transaction error, trigger a re-login.
                    else:
                        # queue for relogin if "needs auth" code.
                        if alert_resp_code in [401, 403] and not sdk_vars["auth_token"]:
                            logged_in = False
                        sys.stdout.write("{0} - CloudGenix ALERT API request error ({1}). "
                                         "(Last event at {2})\n"
                                         "".format(str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT)),
                                                   alert_resp_code,
                                                   alert_last_event_date.strftime(SYSLOG_DATE_FORMAT)))
                        local_event_generate(info={"NOTICE": "CloudGenix ALERT API request error "
                                                             "({0}).".format(alert_resp_code)},
                                             code="CG_API_SYSLOG_GW_REQUEST_FAILURE",
                                             sdk_vars=sdk_vars)
                    sys.stdout.flush()

            # Not logged in
            else:
                sys.stdout.write("{0} - Could not get events, not currently logged in or invalid Auth_Token.\n".format(
                    str(datetime.datetime.utcnow().strftime(SYSLOG_DATE_FORMAT))))
                local_event_generate(info={"NOTICE": "Could not get events, not currently logged in."},
                                     code="CG_API_SYSLOG_GW_LOGIN_FAILURE",
                                     severity="critical",
                                     notice_type="alarm",
                                     sdk_vars=sdk_vars)
                sys.stdout.flush()

            # sleep for next update
            time.sleep(refresh_delay)
    except KeyboardInterrupt:
        local_event_generate(
            info={"NOTICE": "CG API to Syslog Service COLD STOP"},
            code="CG_API_SYSLOG_GW_COLD_STOP",
            sdk_vars=sdk_vars)
        sys.stdout.write("Finished! exiting..\n")
        # logout if not AUTH_TOKEN
        if not sdk_vars["auth_token"]:
            sdk.interactive.logout()
