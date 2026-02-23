import json

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
    module = log_message.split('(')[0]
    submodule = log_message.split(':', 1)[1].split(')', 1)[0]
    message = log_message.split(' ', 1)[1]


    return module, submodule, message