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
    normalizeted_log = normalization.normalize_log(desassemble_log)
    normalization.transport_to_json_file(normalizeted_log)

'''
TODO

tem que arrumar o normalization.py para aceitar os logs do syslog
alguns ele aceita como eu ja fiz o teste,
mas outros (quais? eu nao sei, tem q ver) ele da erro de UNPACKING
'''