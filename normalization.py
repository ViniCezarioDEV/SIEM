import re
import json
import os


JSON_FILE = "logs.json"


# ==============================
# BASE SCHEMA
# ==============================
def base_schema():
    return {
        "timestamp": None,
        "hostname": None,
        "service": None,

        "event_category": None,
        "event_type": None,
        "event_action": None,

        "source_user": None,
        "target_user": None,

        "process": None,
        "pid": None,

        "result": None,

        "raw_message": None
    }


# ==============================
# PARSE RAW LOG LINE
# ==============================
def parse_log_line(log_line):

    # Example:
    # 2026-02-25T16:31:14.843539-03:00 L5450 sudo[1234]: message

    pattern = r"^(\S+) (\S+) ([^\[\s]+)(?:\[(\d+)\])?: (.+)$"
    match = re.match(pattern, log_line)

    if not match:
        #print(log_line) # for DEBUG
        return None

    timestamp, hostname, service, pid, message = match.groups()

    return {
        "timestamp": timestamp,
        "hostname": hostname,
        "service": service,
        "pid": pid,
        "message": message
    }


# ==============================
# EVENT CLASSIFICATION
# ==============================
def classify_event(service, message):

    # Authentication failure
    if "password check failed" in message:
        return "authentication", "authentication_failure", "password_check"

    # Sudo incorrect password
    if "incorrect password attempt" in message:
        return "privilege_escalation", "sudo_authentication", "sudo_attempt"

    # Sudo session opened
    if "session opened for user" in message:
        return "session", "session_open", "privileged_session"

    # Sudo session closed
    if "session closed for user" in message:
        return "session", "session_close", "privileged_session"

    # System suspend
    if "suspend" in message.lower():
        return "system", "power_state_change", "suspend"

    # System reboot
    if "reboot" in message.lower():
        return "system", "power_state_change", "reboot"

    # System power
    if "power" in message.lower():
        return "system", "power_state_change", "power"

    # USB device
    if "New USB device found" in message:
        return "device", "usb_connection", "device_connected"

    return "system", "generic_event", "unknown"


# ==============================
# FIELD EXTRACTION
# ==============================
def extract_fields(event, message):

    # Authentication failure
    auth_fail = re.search(r"user \((.*?)\)", message)
    if auth_fail:
        event["source_user"] = auth_fail.group(1)
        event["result"] = "failed"
        return event

    # Sudo incorrect password
    sudo_fail = re.search(
        r"(\d+) incorrect password attempt[s]?", message)
    if sudo_fail:
        event["result"] = "failed"
        event["attempt_count"] = int(sudo_fail.group(1))
        return event

    # Session opened
    session_open = re.search(
        r"session opened for user (\w+).* by (\w+)", message)
    if session_open:
        event["target_user"] = session_open.group(1)
        event["source_user"] = session_open.group(2)
        event["result"] = "success"
        return event

    # Session closed
    session_close = re.search(
        r"session closed for user (\w+)", message)
    if session_close:
        event["target_user"] = session_close.group(1)
        event["result"] = "success"
        return event

    # USB connection
    usb = re.search(
        r"idVendor=(\w+), idProduct=(\w+)", message)
    if usb:
        event["vendor_id"] = usb.group(1)
        event["product_id"] = usb.group(2)
        event["result"] = "success"
        return event

    event["result"] = "unknown"
    return event


# ==============================
# MAIN NORMALIZATION
# ==============================
def normalize_log(log_line):

    parsed = parse_log_line(log_line)
    if not parsed:
        return None

    event = base_schema()

    # Base fields
    event["timestamp"] = parsed["timestamp"]
    event["hostname"] = parsed["hostname"]
    event["service"] = parsed["service"]
    event["pid"] = parsed["pid"]
    event["process"] = parsed["service"]
    event["raw_message"] = parsed["message"]

    # Classification
    category, event_type, action = classify_event(
        parsed["service"], parsed["message"])

    event["event_category"] = category
    event["event_type"] = event_type
    event["event_action"] = action

    # Field extraction
    event = extract_fields(event, parsed["message"])

    return event


# ==============================
# STORE TO JSON
# ==============================
def save_to_json(event):

    if not event:
        return

    if os.path.exists(JSON_FILE):
        with open(JSON_FILE, "r") as f:
            data = json.load(f)

        if not isinstance(data, list):
            data = [data]

        data.append(event)

    else:
        data = [event]

    with open(JSON_FILE, "w") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)