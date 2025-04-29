import os
import subprocess
import time
import datetime
import win32api
import win32file
import wmi
import requests
import uuid
import usb.core
import usb.utilz
import threading
import json
import psutil
import smtplib
from email.message import EmailMessage

# Supabase configuration
SUPABASE_URL = "" # Insert your Supabase URL
SUPABASE_API_KEY = "" # Insert your Supabase API Key

# Email configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USERNAME = "" # Insert client-side email
EMAIL_PASSWORD = "" # Insert client-side email password or key
ADMIN_EMAIL = "" # Insert email account to send email to

blocked_drives = set()

def count_files(drive):
    total = 0
    for root, dirs, files in os.walk(drive):
        total += len(files)
    return total

def get_mac_address():
    """Retrieve the MAC address of the primary network interface."""
    try:
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK:  # Check for MAC address
                    return addr.address
    except Exception as e:
        print(f"Error fetching MAC address: {e}")
    return "Unknown MAC Address"


def upload_to_supabase_with_retry(data, max_retries=5, delay=2):
    """Upload log data to Supabase with retry logic."""
    retries = 0
    while retries < max_retries:
        try:
            headers = {
                "apikey": SUPABASE_API_KEY,
                "Authorization": f"Bearer {SUPABASE_API_KEY}",
                "Content-Type": "application/json"
            }
            response = requests.post(f"{SUPABASE_URL}/rest/v1/usb_logs", headers=headers, json=data)
            if response.status_code == 201:
                print("Log successfully uploaded to Supabase.")
                return True
            else:
                print(f"Failed to upload log: {response.status_code}, {response.text}")
        except Exception as e:
            print(f"Error uploading log to Supabase: {e}")
        
        retries += 1
        print(f"Retrying in {delay} seconds... (Attempt {retries}/{max_retries})")
        time.sleep(delay)
        delay *= 2  # Exponential backoff
    
    print("Failed to upload log after maximum retries.")
    save_log_locally(data)
    return False

def retry_failed_logs():
    """Retry uploading failed logs from the local file."""
    try:
        # Open the file containing failed logs
        with open("failed_logs.txt", "r") as file:
            logs = file.readlines()
        
        # Prepare to rewrite the file with only failed logs
        remaining_logs = []

        for log in logs:
            try:
                log_data = json.loads(log.strip())  # Convert string back to dictionary
                success = upload_to_supabase_with_retry(log_data)
                if not success:
                    remaining_logs.append(log)  # Keep failed logs for another retry
            except Exception as e:
                print(f"Error processing log: {e}")
                remaining_logs.append(log)  # Keep logs that caused unexpected issues

        # Overwrite the file with remaining failed logs
        with open("failed_logs.txt", "w") as file:
            file.writelines(remaining_logs)

        print("Retry process completed. Remaining failed logs:", len(remaining_logs))
    except FileNotFoundError:
        print("No failed logs found.")
    except Exception as e:
        print(f"Error during retry process: {e}")


def save_log_locally(data):
    """Save failed log locally for retry or manual processing."""
    with open("failed_logs.txt", "a") as file:
        file.write(json.dumps(data) + "\n")
    print("Log saved locally for future retry.")


def schedule_retries(interval=1800):
    """Schedule retries for failed logs every `interval` seconds."""
    def retry_task():
        while True:
            print("Starting retry for failed logs...")
            retry_failed_logs()
            time.sleep(interval)  # Wait for the specified interval

    # Start the retry task in a separate thread
    retry_thread = threading.Thread(target=retry_task, daemon=True)
    retry_thread.start()


def is_mass_storage(device_path):
    """Check if the connected device is a USB mass storage or fixed drive."""
    drive_type = win32file.GetDriveType(device_path)
    return drive_type in [win32file.DRIVE_REMOVABLE, win32file.DRIVE_FIXED]



def scan_usb_with_defender(drive):
    """Scan a USB drive using MpCmdRun.exe (Windows Defender) and remove threats."""
    try:
        print(f"Scanning USB drive {drive} with MpCmdRun.exe...")
        # Use -DisableRemediation False to allow Defender to remove threats
        scan_command = [
            r"C:\Program Files\Windows Defender\MpCmdRun.exe",
            "-Scan", "-ScanType", "3",  # Full scan
            "-File", drive,
            "-Remove"
        ]
        print(f"Running command: {' '.join(scan_command)}")  # Debug: Print the command
        result = subprocess.run(scan_command, capture_output=True, text=True)
        output = result.stdout + result.stderr

        # Debugging output
        print("Scan output:\n", output)

        # Logic to check for threat and cleaning
        threat_found = "threat" in output.lower()
        cleaning_started = "cleaning started" in output.lower() or "remediation started" in output.lower()
        cleaning_completed = "cleaning finished" in output.lower() or "remediation completed" in output.lower()

        if threat_found:
            if cleaning_started or cleaning_completed:
                return True, "Threats detected and removed by Windows Defender."
            else:
                return True, "Threats detected, but no cleaning confirmed."
        else:
            return False, "No threats found."

    except Exception as e:
        return True, f"Error during scan: {e}"



def send_alert_email(subject, body):
    """Send an email alert to the administrator."""
    try:
        print(f"Sending email with subject: {subject}")  # Debug
        print(f"Email body: {body}")  # Debug
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = EMAIL_USERNAME
        msg["To"] = ADMIN_EMAIL
        msg.set_content(body)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.set_debuglevel(1)  # Enable SMTP debug output
            server.starttls()
            print("Logged into SMTP server.")  # Debug
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            server.send_message(msg)
            
        print("Email alert sent successfully.")
    except Exception as e:
        print(f"Error sending email: {e}")  # Debug



def monitor_usb():
    """Continuously monitor for USB connections."""
    known_drives = set(win32api.GetLogicalDriveStrings().split("\x00")[:-1])
    
    while True:
        current_drives = set(win32api.GetLogicalDriveStrings().split("\x00")[:-1])
        print(f"Known Drives: {known_drives}")
        print(f"Current Drives: {current_drives}")
        new_drives = current_drives - known_drives
        print(f"New Drives: {new_drives}\n")
        
        for drive in new_drives:
            if drive in blocked_drives:
                print(f"Drive {drive} is already blocked. Skipping...")
                continue

            if is_mass_storage(drive):
                # Ensure the drive path ends with a backslash
                if not drive.endswith("\\"):
                    drive += "\\"
                
                mac_address = get_mac_address()
                has_virus, scan_report = scan_usb_with_defender(drive)
                
                log_data = {
                    "device": drive,
                    "mac_address": mac_address,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "alert": "Virus detected" if has_virus else "No issues",
                    "report": scan_report if scan_report else "Clean"
                }
                
                if has_virus:
                    print(f"Threat detected on USB drive {drive}.")
                else:
                    print(f"No virus detected on USB drive {drive}.")

                # Send an email alert for every USB connection
                subject = f"USB Connection Alert for Drive {drive}"
                body = (
                    f"A USB device was connected.\n"
                    f"Drive: {drive}\n"
                    f"MAC Address: {mac_address}\n"
                    f"Alert: {'Virus detected' if has_virus else 'No issues'}\n"
                    f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}"
                )
                send_alert_email(subject, body)

                # Upload log to Supabase
                upload_to_supabase_with_retry(log_data)
        
        known_drives = current_drives
        time.sleep(5)


if __name__ == "__main__":
    # Schedule periodic retries for failed logs
    schedule_retries()
    
    # Start monitoring USB devices
    monitor_usb()


