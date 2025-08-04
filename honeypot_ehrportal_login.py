import socket
import platform
import datetime
import os
from pathlib import Path

def get_host_info():
    """Collects host information from the accessing system."""
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        system_info = platform.platform()
        return {
            "hostname": hostname,
            "ip_address": ip_address,
            "system": system_info,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    except Exception as e:
        return {
            "hostname": "Unknown",
            "ip_address": "Unknown",
            "system": str(e),
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

def generate_log_filename(ip_address):
    """Generates a unique filename based on date, time, and IP address."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = Path("logs")
    base_dir.mkdir(exist_ok=True)
    
    # Count existing logs for this IP to handle repeat attempts
    existing_logs = [f for f in base_dir.glob(f"ehr_login_attempt_{ip_address}_*.txt")]
    if existing_logs:
        attempt_count = len(existing_logs) + 1
    else:
        attempt_count = 1  # <-- Fix: set to 1 if no logs exist

    filename = base_dir / f"ehr_login_attempt_{ip_address}_{timestamp}_attempt{attempt_count}.txt"
    return filename, attempt_count

def log_attempt(host_info, username, password):
    """Logs the login attempt and host information to a text file."""
    filename, attempt_count = generate_log_filename(host_info["ip_address"])
    attempt_info = f"Attempt #{attempt_count}" if attempt_count > 1 else "First Attempt"
    
    with open(filename, "w") as f:
        f.write(f"[company name] EHR System Login Attempt Log\n")
        f.write(f"{'='*50}\n")
        f.write(f"Timestamp: {host_info['timestamp']}\n")
        f.write(f"Attempt: {attempt_info}\n")
        f.write(f"{'-'*50}\n")
        f.write(f"Host Information:\n")
        f.write(f"  IP Address: {host_info['ip_address']}\n")
        f.write(f"  Hostname: {host_info['hostname']}\n")
        f.write(f"  System: {host_info['system']}\n")
        f.write(f"{'-'*50}\n")
        f.write(f"Login Credentials:\n")
        f.write(f"  Username: {username}\n")
        f.write(f"  Password: {password}\n")
        f.write(f"{'='*50}\n")
    
    return filename

def display_login_screen():
    """Displays a fictitious EHR login screen."""
    print("\n[company name] Electronic Health Record (EHR) System")
    print("="*50)
    print("Authorized Personnel Only - HIPAA Compliant")
    print("All access is logged and monitored")
    print("="*50)
    username = input("Username: ")
    password = input("Password: ")
    return username, password

def main():
    """Main function to run the honeypot login system."""
    try:
        while True:
            # Display login screen and capture credentials
            username, password = display_login_screen()
            
            # Get host information
            host_info = get_host_info()
            
            # Log the attempt
            filename = log_attempt(host_info, username, password)
            print(f"\nAccess Denied: Invalid credentials. (Logged to {filename})")
            print("Please contact [company name] IT support for assistance.\n")
            
            # Simulate a delay to mimic real system behavior
            import time
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[company name] EHR System: Session terminated.")
    except Exception as e:
        print(f"\nError: {str(e)}")
        print("Contact [company name] IT support for assistance.")

if __name__ == "__main__":
    main()