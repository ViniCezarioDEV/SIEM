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
    noise_keywords = [
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

            if re.search(r'\bc\d+\b', line):
                ignore = True
                break

        if not ignore:
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
        # Sistema e Manutenção
        ".timer", ".path", "packagekit", "flatpak-helper", "systemd-hostnamed",
        "systemd-localed", "logrotate", "apt-daily", "man-db", "upower", "thermald",
        "audit", "systemd-udevd", "plymouth", "cron.service", "dbus.service",
        "accounts-daemon", "power-profiles", "Stopped user@", "Stopped user-runtime-dir",

        # Hardware e Drivers (Ruído)
        "irqbalance", "touchegg", "switcheroo-control", "ModemManager", "avahi-daemon",
        "colord", "cups", "bluetooth.target", "iio-sensor-proxy", "bolt.service",
        "iwlwifi", "fsckd", "timesyncd", "resolved", "dmesg", "wpa_supplicant",
        "logind", "udisks2", "rfkill", "speech-dispatcher", "lightdm",
        "flatpak-helper", "blueman", "kerneloops", "fwupd"

        # Interface Gráfica e Apps de Usuário
        "xdg-desktop-portal", "xdg-permission-store", "xdg-document-portal",
        "dconf.service", "at-spi-dbus-bus", "rtkit-daemon", "pipewire", "wireplumber",
        "Chromium", "Discord", "Telegram", "qbittorrent", "gnome-terminal", "vte-spawn",
        "xapp-gtk3-module", "WebKitWebProcess", "gvfs", "evolution", "gnome-keyring",
        "xdg-desktop-por", "NetworkManager-dispatcher", "Stopped target", "Reached target",
        "Failed to load module",
    ]

    for line in filtered_log_lines:
        ignore = False

        for keyword in noise_keywords:
            if keyword.lower() in line.lower():
                ignore = True
                break

        if not ignore:
            final_filtered.append(line)

    return final_filtered


auth_log_file_lines = get_all_auth_logs()
filtered_auth_log_lines = auth_log_filter(auth_log_file_lines)

syslog_file_lines = get_all_sys_logs()
filtered_syslog_log_lines = syslog_log_filter(syslog_file_lines)

with open('logs.log', 'w') as file:
    file.write('')
for i in filtered_syslog_log_lines:
    with open('logs.log', 'a+') as file:
        file.write(i + '\n')


"""
TODO

arrumar os ruidos dos logs do syslog, ta cheio de coisa aleatoria
"""