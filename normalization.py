import json
import os

def desassemble_log(log):
    # if exist PID in log
    if '[' in log:
        parts = log.split(' ', 2)
        if len(parts) >= 3:
            timestamp, hostname, log_info = log.split(' ', 2)

            log_info_parts = log_info.split(': ', 1) # spliting ["systemd-logind[906]", "The system will suspend now!"]
            service_and_pid, event = log_info_parts # unpacking info & getting event message
            service_and_pid_parts = service_and_pid.split('[', 1) # spliting service and pid
            service, pid = service_and_pid_parts # getting service info & raw pid info
            pid = pid.split(']')[0] # getting pid value
            return timestamp, hostname, service, pid, event

    # normal log
    parts = log.split(' ', 3)
    if len(parts) >= 4:
        timestamp, hostname, service, log_info = log.split(' ', 3)
        return timestamp, hostname, str(service).split(':')[0], log_info
    return

def detect_service(log_message):
    # SUDO incorrect password attempt on terminal
    if 'incorrect password attempt' in log_message:
        event, _, pwd, target, command = log_message.split(' ; ')

        threat_user, event = event.split(' : ')
        pwd = pwd.split('=', 1)[1]
        target = target.split('=', 1)[1]
        command = command.split('=', 1)[1]

        return threat_user.strip(), event, pwd, target, command

    # any else log
    module = log_message.split('(')[0]
    submodule = log_message.split(':', 1)[1].split(')', 1)[0]
    message = log_message.split(' ', 1)[1]

    return module, submodule, message

def normalize_log(desassemble_log):

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

        return normalized_log

    else:
        timestamp, hostname, service, message = desassemble_log
        detected_services = detect_service(message)

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

        return normalized_log


def transport_to_json_file(normalized_log):
    JSON_FILE = 'logs.json'

    # updating json file
    if os.path.exists(JSON_FILE):
        with open(JSON_FILE, 'r') as file:
            og_file = json.load(file)  # getting actual data in json file

        # Ensure og_file is a list
        if not isinstance(og_file, list):
            og_file = [og_file]

        # Append new log to the list
        og_file.append(normalized_log)

        with open(JSON_FILE, 'w') as file:
            file.write(json.dumps(og_file, ensure_ascii=False, indent=4))

    # creating json file (start with a list)
    else:
        with open(JSON_FILE, 'w') as file:
            file.write(json.dumps([normalized_log], ensure_ascii=False, indent=4))