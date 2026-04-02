import collector
import normalization
import correlation

# Variables
AUTH_LOG_PATH = "/var/log/auth.log"
SYSLOG_PATH = "/var/log/syslog"
ALERTS_FILE = 'alerts.log'

# COLLECTING LOGS
auth_log_file_lines = collector.get_all_auth_logs(log_path=AUTH_LOG_PATH)
syslog_file_lines = collector.get_all_sys_logs(log_path=SYSLOG_PATH)

# FILTERING LOGS
filtered_auth_log_lines = collector.auth_log_filter(auth_log_file_lines)
filtered_syslog_log_lines = collector.syslog_log_filter(syslog_file_lines)

# NORMALIZING AND CORRELATING AUTH LOGS
for log in filtered_auth_log_lines:
    normalized_log = normalization.normalize_log(log)

    if normalized_log:
        normalization.save_to_json(normalized_log)
        alerts = correlation.check_rules(normalized_log)

        for alert in alerts:
            with open(ALERTS_FILE, "a", encoding="utf-8") as file:
                file.write(f"[{alert['alert_type']}] {alert['timestamp']} - {alert['message']}")

# NORMALIZING AND CORRELATING SYSLOGS
for log in filtered_syslog_log_lines:
    normalized_log = normalization.normalize_log(log)

    if normalized_log:
        normalization.save_to_json(normalized_log)

        alerts = correlation.check_rules(normalized_log)

        for alert in alerts:
            with open(ALERTS_FILE, "a", encoding="utf-8") as file:
                file.write(f"[{alert['alert_type']}] {alert['timestamp']} - {alert['message']}")