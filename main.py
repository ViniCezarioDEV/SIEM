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

# NORMALIZING LOGS INTO JSON
for log in filtered_auth_log_lines:
    normalized_log = normalization.normalize_log(log)
    normalization.save_to_json(normalized_log)

'''
TODO

tem que arrumar o normalization.py para aceitar todos os logs
que estao sendo pegos, alguns logs dao o return None
dao None pq o regex nao da match linha 45-46 normalization.py
: tentar dar print nesses logs q estao dando none pra ver oq q ta pegando com eles
: e assim fazer um novo regex sla

'''