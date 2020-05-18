
CloudGenix API -> SYSLOG Gateway
------------

#### Synopsis
REST-based APIs provide the most flexible model for interacting with disparate applications. This is particularly true of traditional network monitoring and provisioning solutions, which have grown organically over time and have limitations of supported versions for capabilities such as SNMP, Netflow, and more. By leveraging CloudGenix APIs, it is much easier to integrate into an existing eco-system of tools.

#### Requirements
* Active CloudGenix Account
* Python >= 2.7 (this script is not yet Python3 compatible)
* Python modules:
    * cloudgenix >=4.7.1b1 - <https://github.com/CloudGenix/sdk-python>
    * cloudgenix-idname >=1.1.2 - <https://github.com/ebob9/cloudgenix-idname>
* A compute system with the following:
  * Virtual or Physical hardware.
    * x86, amd_64, or ARM architecture.
    * x86/amd_64: 2 vCPU/cores, 2 GB memory, 8 GB storage.
  * ARM: 2 vCPU/cores, 2 GB memory, 8 GB storage.
  * Python 2.7-capable operating system installed.
    * Tested with Ubuntu 16.04 (x86/amd_64/ARM) and Windows (amd_64).
    * Recommended ‘pip’ python package manager.

#### Installation Steps

1. Download the CloudGenix API Gateway code bundle.
2. Extract the code bundle to a directory.
3. In the extracted directory, use pip to ensure required packages are installed. (`pip install --upgrade -r ./requirements.txt`)
4. Create a cloudgenix_settings.py file with a dedicated, read-only account.
5. Launch the gateway, specifying the IP or Hostname of the Syslog server. `./cg-syslog-apigw.py -S 172.16.157.129`

Once set up and running, the gateway will emit SYSLOG alerts and alarms automatically as they are generated in the CloudGenix network.

#### License
MIT

#### Version
Version | Changes
------- | --------
**1.2.2**| Added IDs for alarms & alerts, Separate timer for idname updates
**1.2.1**| Minor fixes, and clarification on OPERATOR log merging with AUDIT.
**1.2.0**| Update for May 2018 controller release. Changes include: RFC-5424 now default, operator log merged to audit log, hostname detection, and others.
**1.1.2**| Fix Issue #3
**1.1.1**| Fix Issue #2
**1.1.0**| Update for AUTH_TOKEN support (requires cloudgenix >= v4.6.1b1), fix Issue #1
**1.0.0**| Initial Release.

#### Full Configuration Options
```
SYSLOG:
  These options set where to send SYSLOG messages

  --server SERVER, -S SERVER
                        SYSLOG server. Required.
  --port PORT, -P PORT  Port on SYSLOG server. Default is 514.
  --use-tcp, -T         Send TCP Syslog instead of UDP.
  --facility FACILITY, -F FACILITY
                        SYSLOG Facility to use server. Default is 'user'.
  --date-format DATE_FORMAT
                        Date formatting using 'strftime' style strings, See
                        http://strftime.org/ .Default is '%b %d %H:%M:%S'.
  --rfc5424             RFC 5424 Compliant Syslog messages
  --from-hostname FROM_HOSTNAME
                        From Hostname string, required if RFC 5424 log format.

Parsing:
  These options change how this program parses messages

  --emitjson, -J        Emit messages as JSON
  --disable-name, -DNAME
                        Disable translation of ID to Name.
  --enable-operator, -EOPERATOR
                        Enable Sending Operator Log
  --enable-audit, -EAUDIT
                        Enable Sending Audit Log
  --disable-alarm, -DALARM
                        Disable Sending Alert Log
  --disable-alert, -DALERT
                        Disable Sending Alert Log
  --legacy-events, -LE  Use Legacy Events API (v2.0)

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex.
                        https://controller.cloudgenix.com:8443
  --hours HOURS, -H HOURS
                        Number of Hours to go back in history on cold start
                        (1-240)
  --delay DELAY, -L DELAY
                        Number of seconds to wait between API refreshes
                        (60-65535)

Login:
  These options allow skipping of interactive login

  --email EMAIL, -E EMAIL
                        Use this email as User Name instead of
                        cloudgenix_settings.py
  --pass PASS, -PW PASS
                        Use this Password instead of cloudgenix_settings.py
  --insecure, -I        Do not verify SSL certificate
  --noregion, -NR       Ignore Region-based redirection.

Debug:
  These options enable debugging output

  --rest, -R            Show REST requests
  --debug DEBUG, -D DEBUG
                        Verbose Debug info, levels 0-2

```
