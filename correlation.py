from datetime import datetime
import re

event_memory = []


# ==============================
# MAIN CHECK
# ==============================
def check_rules(new_event):
    global event_memory

    event_memory.append(new_event)
    cleanup_old_events()

    alerts = []

    alerts.extend(rule_brute_force())
    alerts.extend(rule_usb_activity(new_event))
    alerts.extend(rule_success_after_brute_force())
    alerts.extend(rule_account_modification(new_event))
    alerts.extend(rule_sudo_outside_business_hours(new_event))
    alerts.extend(rule_sudo_brute_force(new_event))
    alerts.extend(rule_account_management(new_event))

    return alerts


# ==============================
# CLEANUP
# ==============================
def cleanup_old_events():
    global event_memory

    if len(event_memory) > 1000:
        event_memory.pop(0)


# ==============================
# CORRELATION RULES
# ==============================
def rule_brute_force():
    global event_memory

    detected_alerts = []
    user_failures = {}

    for event in event_memory:
        if event.get('event_type') == 'authentication_failure':
            user = event.get('source_user') or "unknown"
            user_failures[user] = user_failures.get(user, 0) + 1

            # when hits 3 times, an alert will be generated
            if user_failures[user] >= 3:
                detected_alerts.append({
                    "alert_type": "CRITICAL",
                    "message": f"Possible brute-force attack detected against the user: {user}",
                    "timestamp": event.get('timestamp')
                })

                event_memory = [
                    e for e in event_memory
                    if not (e.get('event_type') == 'authentication_failure' and e.get('source_user') == user)
                ]

                user_failures[user] = 0

    return detected_alerts

def rule_usb_activity(current_event):
    if current_event.get('event_type') == 'usb_connection':
        vendor = current_event.get('vendor_id') or "unknown"

        return [{
            "alert_type": "INFO",
            "message": f"New USB device conected (Vendor ID: {vendor})",
            "timestamp": current_event.get('timestamp')
        }]

    return []

def rule_success_after_brute_force():
    global event_memory

    detected_alerts = []
    user_failures = {}
    users_to_clear = []

    for event in event_memory:
        event_type = event.get('event_type')

        if event_type == 'authentication_failure':
            user = event.get('source_user')
            if user:
                user_failures[user] = user_failures.get(user, 0) + 1

        elif event_type == 'session_open' and event.get('result') == 'success':
            user = event.get('target_user')

            # when hits 3 times, an alert will be generated
            if user and user_failures.get(user, 0) >= 3:
                detected_alerts.append({
                    "alert_type": "CRITICAL",
                    "message": f"Successful login to account '{user}' after {user_failures[user]} consecutive failures.",
                    "timestamp": event.get('timestamp')
                })

                user_failures[user] = 0

                users_to_clear.append(user)

    if users_to_clear:
        event_memory = [
            e for e in event_memory
            if e.get('source_user') not in users_to_clear and e.get('target_user') not in users_to_clear
        ]

    return detected_alerts

def rule_account_modification(current_event):
    raw_msg = current_event.get('raw_message', '').lower()

    if 'useradd' in raw_msg or 'new user' in raw_msg:
        return [{
            "alert_type": "HIGH",
            "message": "New user account created on system",
            "timestamp": current_event.get('timestamp')
        }]

    if 'usermod' in raw_msg or 'add to group' in raw_msg:
        return [{
            "alert_type": "MEDIUM",
            "message": "Permissions or users groups modified",
            "timestamp": current_event.get('timestamp')
        }]

    return []

def rule_sudo_outside_business_hours(current_event):
    if current_event.get('event_type') != 'sudo_authentication' and current_event.get('service') != 'sudo':
        return []

    timestamp_str = current_event.get('timestamp')
    if not timestamp_str:
        return []

    time_match = re.search(r'T(\d{2}):', timestamp_str)

    if time_match:
        hour = int(time_match.group(1))

        # If it's before 6:00 AM or after 8:00 PM
        if hour < 6 or hour > 20:
            user = current_event.get('source_user') or "unknown"
            return [{
                "alert_type": "MEDIUM",
                "message": f"Sudo privileges used outside of business hours by the user '{user}'",
                "timestamp": timestamp_str
            }]

    return []

def rule_sudo_brute_force(current_event):
    if current_event.get('event_type') == 'sudo_authentication' and current_event.get('result') == 'failed':

        attempts = current_event.get('attempt_count', 0)
        user = current_event.get('source_user') or "unknown"

        if attempts >= 3:
            return [{
                "alert_type": "HIGH",
                "message": f"Attempt to escalate privileges failed! User '{user}' entered the wrong sudo password {attempts} times",
                "timestamp": current_event.get('timestamp')
            }]

    return []


def rule_account_management(current_event):
    event_type = current_event.get('event_type')

    if event_type == 'account_creation':
        user = current_event.get('target_user') or "unknown"
        return [{
            "alert_type": "HIGH",
            "message": f"New user account created: '{user}'",
            "timestamp": current_event.get('timestamp')
        }]

    if event_type == 'account_modification':
        user = current_event.get('target_user') or "unknown"
        detail = current_event.get('raw_message', '')
        return [{
            "alert_type": "CRITICAL",
            "message": f"User privileges changed. '{user}'! {detail}",
            "timestamp": current_event.get('timestamp')
        }]

    return []