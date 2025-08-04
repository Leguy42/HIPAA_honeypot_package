from flask import Flask, request, render_template_string
import datetime
from pathlib import Path

app = Flask(__name__)

def get_host_info():
    """Collects host information from the accessing client."""
    try:
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        return {
            "ip_address": ip_address,
            "user_agent": user_agent,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    except Exception as e:
        return {
            "ip_address": "Unknown",
            "user_agent": str(e),
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

def generate_log_filename(ip_address):
    """Generates a unique filename based on date, time, and IP address."""
    safe_ip = ip_address.replace(':', '_')
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = Path("logs")
    base_dir.mkdir(exist_ok=True)
    existing_logs = [f for f in base_dir.glob(f"ehr_login_attempt_{safe_ip}_*.txt")]
    attempt_count = len(existing_logs) + 1 if existing_logs else 1
    filename = base_dir / f"ehr_login_attempt_{safe_ip}_{timestamp}_attempt{attempt_count}.txt"
    return filename, attempt_count

def log_attempt(host_info, username, password):
    """Logs the login attempt and host information to a text file."""
    try:
        filename, attempt_count = generate_log_filename(host_info["ip_address"])
        attempt_info = f"Attempt #{attempt_count}" if attempt_count > 1 else "First Attempt"
        with open(filename, "w") as f:
            f.write(f"FakeHealth EHR System Login Attempt Log\n")
            f.write(f"{'='*50}\n")
            f.write(f"Timestamp: {host_info['timestamp']}\n")
            f.write(f"Attempt: {attempt_info}\n")
            f.write(f"{'-'*50}\n")
            f.write(f"Host Information:\n")
            f.write(f"  IP Address: {host_info['ip_address']}\n")
            f.write(f"  User-Agent: {host_info['user_agent']}\n")
            f.write(f"{'-'*50}\n")
            f.write(f"Login Credentials:\n")
            f.write(f"  Username: {username}\n")
            f.write(f"  Password: {password}\n")
            f.write(f"{'='*50}\n")
        return filename
    except Exception as e:
        return f"Error logging attempt: {e}"

LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FakeHealth EHR Portal</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 flex items-center justify-center h-screen">
    <div class="bg-white p-8 rounded-lg shadow-lg w-full max-w-md">
        <h1 class="text-2xl font-bold text-center text-gray-800 mb-4">FakeHealth EHR Portal</h1>
        <p class="text-center text-sm text-gray-600 mb-4">Authorized Personnel Only - HIPAA Compliant</p>
        <p class="text-center text-sm text-red-600 mb-6">All access is logged and monitored</p>
        {% if error %}
        <p class="text-center text-red-500 mb-4">{{ error }}</p>
        {% endif %}
        <form action="/login" method="POST" class="space-y-4">
            <div>
                <label for="username" class="block text-sm font-medium text-gray-700">Username</label>
                <input type="text" name="username" id="username" class="mt-1 block w-full p-2 border border-gray-300 rounded-md" required>
            </div>
            <div>
                <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
                <input type="password" name="password" id="password" class="mt-1 block w-full p-2 border border-gray-300 rounded-md" required>
            </div>
            <button type="submit" class="w-full bg-blue-600 text-white p-2 rounded-md hover:bg-blue-700">Login</button>
        </form>
        <p class="text-center text-sm text-gray-600 mt-4">Contact FakeHealth IT Support for assistance</p>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    """Renders the login page."""
    return render_template_string(LOGIN_PAGE, error=None)

@app.route('/login', methods=['POST'])
def login():
    """Handles login attempts and logs credentials."""
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    host_info = get_host_info()
    filename = log_attempt(host_info, username, password)
    error = f"Access Denied: Invalid credentials. (Logged to {filename})"
    return render_template_string(LOGIN_PAGE, error=error)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)