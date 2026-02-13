import re

AUTH_LOG_PATH = "/var/log/auth.log"
KERNEL_PATH = "/var/log/syslog"

def get_all_auth_logs():
    with open(AUTH_LOG_PATH, 'r', encoding='utf-8', errors='replace') as file:
        lines = file.readlines()
        for i, line in enumerate(lines):
            line = line.replace('\n', '')
            lines[i] = line

    return lines

def auth_log_filter(log_lines):
    filtered_log_lines = []
    final_filtered = []

    # first filter - takes only relevant logs
    for line in log_lines:
        if 'sudo:session' in line:                      # when someone uses "sudo + command"
            filtered_log_lines.append(line)             #
        elif 'su:session' in line:                      # when someone becomes root
            filtered_log_lines.append(line)             #
        elif line in ['incorrect password', 'sudo']:    # when someone enters the wrong password (terminal)
            filtered_log_lines.append(line)             #
        elif 'lightdm:session' in line:                 # when someone has successfully logged into the system
            filtered_log_lines.append(line)             #
        elif 'unix_chkpwd' in line:                     # when someone enters the wrong password (system)
            filtered_log_lines.append(line)             #
        elif 'systemd-logind' in line:                  # system status (lid opened/closed), the system will (restart/suspend/etc)
            filtered_log_lines.append(line)

    # second filter - removes irrelevant logs
    for line in filtered_log_lines:
        if 'buttons' in line or 'seat' in line or 'Lid' in line:
            continue
        if re.search(r'\bc\d+\b', line):
            continue
        final_filtered.append(line)

    return final_filtered

def get_all_sys_logs():
    with open(KERNEL_PATH, 'r', encoding='utf-8', errors='replace') as file:
        lines = file.readlines()
        for i, line in enumerate(lines):
            line = line.replace('\n', '')
            lines[i] = line

    return lines

def kernel_log_filter(log_lines):
    filtered_log_lines = []

    for line in log_lines:
        if 'New USB device found' in line:
            filtered_log_lines.append(line)

    return filtered_log_lines


auth_log_file_lines = get_all_auth_logs()
filtered_auth_log_lines = auth_log_filter(auth_log_file_lines)

kernel_file_lines = get_all_sys_logs()
filtered_kernel_log_lines = kernel_log_filter(kernel_file_lines)
for i in filtered_kernel_log_lines:
    print(i)

