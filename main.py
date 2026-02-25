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
    desassemble_log = normalization.desassemble_log(log)

    # any log with PID information
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
        detected_services = normalization.detect_service(message)

        # SUDO incorrect password attempt on terminal log
        if len(detected_services) == 5:
            threat_user, event, pwd, target, command = detected_services

            normalized_log = {
                "timestamp": timestamp,
                "hostname": hostname,
                "service": service,
                "threat_user": threat_user,
                "target_user": target,
                "command_executed": command,
                "pwd": pwd,
                "event": event,
            }

        # any else log
        else:
            module, submodule, event = detected_services

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

esses bang de normalized_log = {} adivinha pra onde tem que ir? KKKKKKKKKKKKKKk
deveria ta aqui nao
'''