AUTH_LOG_PATH = "/var/log/auth.log"

def get_all_auth_logs():
    with open(AUTH_LOG_PATH, 'r') as file:
        lines = file.readlines()
        for i, line in enumerate(lines):
            line = line.replace('\n', '')
            lines[i] = line

    return lines

def auth_log_filter(log_lines):
    for line in log_lines:
        pass


auth_log_file_lines = get_all_auth_logs()
for line in auth_log_file_lines:
    print(line)