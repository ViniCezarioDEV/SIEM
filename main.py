import collector
import normalization

# Variables
AUTH_LOG_PATH = "/var/log/auth.log"
SYSLOG_PATH = "/var/log/syslog"


# COLLECTING LOGS
auth_log_file_lines = collector.get_all_auth_logs(log_path=AUTH_LOG_PATH)
syslog_file_lines = collector.get_all_sys_logs(log_path=SYSLOG_PATH)

# FILTERING LOGS
filtered_auth_log_lines = collector.auth_log_filter(auth_log_file_lines)
filtered_syslog_log_lines = collector.syslog_log_filter(syslog_file_lines)

# NORMALAZING LOGS INTO JSON
for log in filtered_auth_log_lines:
    #timestamp, hostname, service, message = normalization.desassemble_log(log)
    desassemble_log = normalization.desassemble_log(log)

    if len(desassemble_log) == 5:
        timestamp, hostname, service, pid, log_info = desassemble_log
        normalized_log = {
            "timestamp": timestamp,
            "hostname": hostname,
            "service": service,
            "pid": pid,
            "event": log_info
        }

        print(normalized_log)

    else:
        timestamp, hostname, service, message = desassemble_log

        module, submodule, event = normalization.detect_service(message)

        normalized_log = {
            "timestamp": timestamp,
            "hostname": hostname,
            "service": service,
            "module": module,
            "submodule": submodule,
            "event": event,
        }

        print(normalized_log)

'''
TODO
Estou sentindo falta do log: 
2026-02-20T16:25:17.393199-03:00 L5450 sudo:    vinas : 1 incorrect password attempt ; TTY=pts/2 ; PWD=/home/vinas/Programming/Python/projects/SIEM ; USER=root ; COMMAND=/usr/bin/tail -f /var/log/auth.log
procurar ele kkkkkkkkkkkkkk
'''