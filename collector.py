import re

AUTH_LOG_PATH = "/var/log/auth.log"
SYSLOG_PATH = "/var/log/syslog"

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
    interesting_keywords = [
        'sudo:session',             # when someone uses "sudo + command"
        'su:session',               # when someone becomes root
        'incorrect password',       # when someone enters the wrong password (terminal)
        'lightdm:session',          # when someone has successfully logged into the system
        'unix_chkpwd',              # when someone enters the wrong password (system)
        'systemd-logind',           # system status (lid opened/closed), the system will (restart/suspend/etc)
    ]

    # first filter - takes only relevant logs
    for line in log_lines:
        for keyword in interesting_keywords:
            if keyword in line:
                filtered_log_lines.append(line)
                break

    # second filter - removes irrelevant logs
    for line in filtered_log_lines:
        if 'buttons' in line or 'seat' in line or 'Lid' in line:
            continue
        if re.search(r'\bc\d+\b', line):
            continue
        final_filtered.append(line)

    return final_filtered

def get_all_sys_logs():
    with open(SYSLOG_PATH, 'r', encoding='utf-8', errors='replace') as file:
        lines = file.readlines()
        for i, line in enumerate(lines):
            line = line.replace('\n', '')
            lines[i] = line

    return lines

def syslog_log_filter(log_lines):
    filtered_log_lines = []
    final_filtered = []
    interesting_keywords = [
        'Started',
        'Stopped',
        'Failed',
        'error',
        'denied',
        'New USB device found',
        'USB disconnect',
        'sshd',
        'useradd',
        'usermod',
    ]

    # first filter - takes only relevant logs
    for line in log_lines:
        for keyword in interesting_keywords:
            if keyword in line:
                filtered_log_lines.append(line)
                break

    # second filter - removes irrelevant logs
    noise_keywords = [
        ".timer",
        ".path",
        "pipewire",
        "wireplumber",
        "gvfs",
        "evolution",
        "gnome-keyring",
        "cups.service",
        "speech-dispatcher",
        "man-db",
        "apt-daily",
        "logrotate",
        "colord",
        "mintsystem",
        "udisks2",
        "buttons",
        "seat",
        "Lid",
    ]

    for line in filtered_log_lines:
        ignore = False

        for keyword in noise_keywords:
            if keyword.lower() in line.lower():
                ignore = True
                break

        if not ignore:
            final_filtered.append(line)

    '''
    for line in filtered_log_lines:
        if 'buttons' in line or 'seat' in line or 'Lid' in line:
            continue
        if re.search(r'\bc\d+\b', line):
            continue
        final_filtered.append(line)'''

    return final_filtered


auth_log_file_lines = get_all_auth_logs()
filtered_auth_log_lines = auth_log_filter(auth_log_file_lines)

syslog_file_lines = get_all_sys_logs()
filtered_syslog_log_lines = syslog_log_filter(syslog_file_lines)
for i in filtered_syslog_log_lines:
    print(i)

"""
TODO

arrumar os ruidos dos logs do syslog, ta cheio de coisa aleatoria
"""