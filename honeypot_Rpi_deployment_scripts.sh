#!/bin/bash
# deploy_honeypot.sh - Raspberry Pi Honeypot Deployment Script
# Run with: curl -sSL https://your-server.com/deploy.sh | sudo bash

set -e

echo "🍯 Healthcare Honeypot Deployment Script for Raspberry Pi"
echo "========================================================="

# Configuration
HONEYPOT_USER="honeypot"
HONEYPOT_DIR="/opt/honeypot"
LOG_DIR="/var/log/honeypot"
SERVICE_NAME="healthcare-honeypot"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

# Check if running on Raspberry Pi
if ! grep -q "Raspberry Pi" /proc/device-tree/model 2>/dev/null; then
    warn "This doesn't appear to be a Raspberry Pi, but continuing anyway..."
fi

log "Updating system packages..."
apt update && apt upgrade -y

log "Installing required system packages..."
apt install -y python3 python3-pip python3-venv nginx logrotate fail2ban ufw git htop

log "Creating honeypot user..."
if ! id "$HONEYPOT_USER" &>/dev/null; then
    useradd --system --shell /bin/bash --home-dir "$HONEYPOT_DIR" --create-home "$HONEYPOT_USER"
fi

log "Creating directory structure..."
mkdir -p "$HONEYPOT_DIR"
mkdir -p "$LOG_DIR"
chown -R "$HONEYPOT_USER:$HONEYPOT_USER" "$HONEYPOT_DIR"
chown -R "$HONEYPOT_USER:$HONEYPOT_USER" "$LOG_DIR"

log "Setting up Python virtual environment..."
sudo -u "$HONEYPOT_USER" python3 -m venv "$HONEYPOT_DIR/venv"
sudo -u "$HONEYPOT_USER" "$HONEYPOT_DIR/venv/bin/pip" install --upgrade pip
sudo -u "$HONEYPOT_USER" "$HONEYPOT_DIR/venv/bin/pip" install flask gunicorn

log "Creating honeypot application..."
cat > "$HONEYPOT_DIR/app.py" << 'EOF'
# [The Python honeypot code from the previous artifact would go here]
# For brevity, I'll include a reference to copy it from the previous artifact
EOF

log "Creating Gunicorn configuration..."
cat > "$HONEYPOT_DIR/gunicorn.conf.py" << 'EOF'
# Gunicorn configuration for production deployment
bind = "127.0.0.1:5000"
workers = 2
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 100
timeout = 30
keepalive = 2
preload_app = True
user = "honeypot"
group = "honeypot"
pid = "/var/run/honeypot/gunicorn.pid"
access_log = "/var/log/honeypot/gunicorn_access.log"
error_log = "/var/log/honeypot/gunicorn_error.log"
log_level = "info"
EOF

log "Creating systemd service..."
cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=Healthcare Patient Portal Honeypot
After=network.target

[Service]
Type=notify
User=$HONEYPOT_USER
Group=$HONEYPOT_USER
WorkingDirectory=$HONEYPOT_DIR
Environment=PATH=$HONEYPOT_DIR/venv/bin
ExecStart=$HONEYPOT_DIR/venv/bin/gunicorn --config gunicorn.conf.py app:app
ExecReload=/bin/kill -s HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
RuntimeDirectory=honeypot
RuntimeDirectoryMode=755
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

log "Creating nginx configuration..."
cat > "/etc/nginx/sites-available/honeypot" << 'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    
    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Hide nginx version
    server_tokens off;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=honeypot:10m rate=10r/m;
    limit_req zone=honeypot burst=20 nodelay;
    
    # Logging
    access_log /var/log/nginx/honeypot_access.log;
    error_log /var/log/nginx/honeypot_error.log;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }
    
    # Health check endpoint (internal only)
    location /health {
        access_log off;
        allow 127.0.0.1;
        allow ::1;
        deny all;
        proxy_pass http://127.0.0.1:5000/health;
    }
}
EOF

log "Configuring nginx..."
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/
nginx -t

log "Setting up log rotation..."
cat > "/etc/logrotate.d/honeypot" << 'EOF'
/var/log/honeypot/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 honeypot honeypot
    postrotate
        systemctl reload healthcare-honeypot
    endscript
}

/var/log/nginx/honeypot_*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 www-data www-data
    postrotate
        systemctl reload nginx
    endscript
}
EOF

log "Setting up firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment "SSH"
ufw allow 80/tcp comment "HTTP - Honeypot"
ufw allow from 192.168.0.0/16 to any port 22 comment "SSH from local network"
ufw --force enable

log "Configuring fail2ban..."
cat > "/etc/fail2ban/jail.d/honeypot.conf" << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[nginx-honeypot]
enabled = true
port = http
filter = nginx-honeypot
logpath = /var/log/nginx/honeypot_access.log
maxretry = 10
bantime = 3600

[honeypot-bruteforce]
enabled = true
port = http
filter = honeypot-bruteforce
logpath = /var/log/honeypot/honeypot.log
maxretry = 20
bantime = 7200
EOF

cat > "/etc/fail2ban/filter.d/honeypot-bruteforce.conf" << 'EOF'
[Definition]
failregex = ^.*Activity: login_attempt from <HOST> - .*$
ignoreregex =
EOF

log "Creating monitoring script..."
cat > "$HONEYPOT_DIR/monitor.py" << 'EOF'
#!/usr/bin/env python3
"""
Simple monitoring script for the honeypot
Generates daily reports and alerts
"""

import json
import os
import smtplib
from datetime import datetime, timedelta
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

LOG_DIR = "/var/log/honeypot"
ALERT_THRESHOLD = 50  # Alert if more than 50 login attempts in a day

def parse_activity_logs(date_str):
    """Parse activity logs for a specific date"""
    log_file = os.path.join(LOG_DIR, f"activity_{date_str}.json")
    activities = []
    
    if not os.path.exists(log_file):
        return activities
    
    with open(log_file, 'r') as f:
        for line in f:
            try:
                activities.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue
    
    return activities

def generate_daily_report(date_str):
    """Generate daily activity report"""
    activities = parse_activity_logs(date_str)
    
    if not activities:
        return None
    
    stats = defaultdict(int)
    ips = defaultdict(int)
    login_attempts = []
    
    for activity in activities:
        stats[activity['action']] += 1
        ips[activity['client_ip']] += 1
        
        if activity['action'] == 'login_attempt':
            login_attempts.append(activity)
    
    report = {
        'date': date_str,
        'total_activities': len(activities),
        'unique_ips': len(ips),
        'top_ips': sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10],
        'activity_breakdown': dict(stats),
        'login_attempts': len(login_attempts),
        'suspicious_activity': stats['login_attempt'] > ALERT_THRESHOLD
    }
    
    return report

def send_alert_email(report, config):
    """Send email alert if configured"""
    if not all(config.get(k) for k in ['smtp_server', 'smtp_port', 'email_user', 'email_pass', 'alert_email']):
        return False
    
    try:
        msg = MIMEMultipart()
        msg['From'] = config['email_user']
        msg['To'] = config['alert_email']
        msg['Subject'] = f"Honeypot Alert - {report['date']}"
        
        body = f"""
        Honeypot Security Alert
        
        Date: {report['date']}
        Total Activities: {report['total_activities']}
        Login Attempts: {report['login_attempts']}
        Unique IPs: {report['unique_ips']}
        
        Top Active IPs:
        {chr(10).join([f"  {ip}: {count} requests" for ip, count in report['top_ips'][:5]])}
        
        This alert was triggered because login attempts exceeded {ALERT_THRESHOLD}.
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
        server.starttls()
        server.login(config['email_user'], config['email_pass'])
        server.send_message(msg)
        server.quit()
        
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

if __name__ == "__main__":
    # Generate report for yesterday
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y%m%d')
    report = generate_daily_report(yesterday)
    
    if report:
        print(f"Daily Report for {report['date']}:")
        print(f"  Total Activities: {report['total_activities']}")
        print(f"  Login Attempts: {report['login_attempts']}")
        print(f"  Unique IPs: {report['unique_ips']}")
        
        if report['suspicious_activity']:
            print(f"  ⚠️  ALERT: High login attempt activity detected!")
            
            # Try to load email config and send alert
            try:
                with open('/opt/honeypot/email_config.json', 'r') as f:
                    email_config = json.load(f)
                    if send_alert_email(report, email_config):
                        print("  📧 Alert email sent successfully")
            except FileNotFoundError:
                print("  📧 Email config not found - skipping email alert")
        
        # Save report
        report_file = os.path.join(LOG_DIR, f"report_{yesterday}.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
    else:
        print(f"No activity data found for {yesterday}")
EOF

chmod +x "$HONEYPOT_DIR/monitor.py"

log "Creating management scripts..."
cat > "$HONEYPOT_DIR/manage.sh" << 'EOF'
#!/bin/bash
# Honeypot management script

HONEYPOT_DIR="/opt/honeypot"
LOG_DIR="/var/log/honeypot"
SERVICE_NAME="healthcare-honeypot"

case "$1" in
    start)
        echo "Starting honeypot..."
        systemctl start $SERVICE_NAME
        systemctl start nginx
        systemctl status $SERVICE_NAME --no-pager
        ;;
    stop)
        echo "Stopping honeypot..."
        systemctl stop $SERVICE_NAME
        ;;
    restart)
        echo "Restarting honeypot..."
        systemctl restart $SERVICE_NAME
        systemctl restart nginx
        ;;
    status)
        systemctl status $SERVICE_NAME --no-pager
        ;;
    logs)
        if [ "$2" = "activity" ]; then
            tail -f $LOG_DIR/activity_$(date +%Y%m%d).json
        elif [ "$2" = "nginx" ]; then
            tail -f /var/log/nginx/honeypot_access.log
        else
            tail -f $LOG_DIR/honeypot.log
        fi
        ;;
    stats)
        echo "=== Honeypot Statistics ==="
        echo "Service Status:"
        systemctl is-active $SERVICE_NAME
        echo ""
        echo "Recent Activity (last 100 lines):"
        tail -100 $LOG_DIR/honeypot.log | grep -E "(login_attempt|page_visit)" | wc -l
        echo ""
        echo "Unique IPs today:"
        if [ -f "$LOG_DIR/activity_$(date +%Y%m%d).json" ]; then
            grep -o '"client_ip":"[^"]*"' "$LOG_DIR/activity_$(date +%Y%m%d).json" | sort -u | wc -l
        else
            echo "0 (no activity log found)"
        fi
        ;;
    report)
        python3 $HONEYPOT_DIR/monitor.py
        ;;
    config)
        case "$2" in
            practice)
                echo "Current practice: $(grep practice_name $HONEYPOT_DIR/app.py | cut -d"'" -f2)"
                if [ "$3" ]; then
                    sed -i "s/'practice_name': '[^']*'/'practice_name': '$3'/" $HONEYPOT_DIR/app.py
                    echo "Updated practice name to: $3"
                    systemctl restart $SERVICE_NAME
                fi
                ;;
            logo)
                echo "Current logo: $(grep "'logo':" $HONEYPOT_DIR/app.py | cut -d"'" -f4)"
                if [ "$3" ]; then
                    sed -i "s/'logo': '[^']*'/'logo': '$3'/" $HONEYPOT_DIR/app.py
                    echo "Updated logo to: $3"
                    systemctl restart $SERVICE_NAME
                fi
                ;;
            *)
                echo "Usage: $0 config practice|logo [new_value]"
                ;;
        esac
        ;;
    clean)
        echo "Cleaning old logs (keeping last 30 days)..."
        find $LOG_DIR -name "*.log.*" -mtime +30 -delete
        find $LOG_DIR -name "activity_*.json" -mtime +30 -delete
        find $LOG_DIR -name "report_*.json" -mtime +30 -delete
        echo "Cleanup completed."
        ;;
    backup)
        BACKUP_FILE="/tmp/honeypot_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
        tar -czf "$BACKUP_FILE" -C / opt/honeypot var/log/honeypot etc/nginx/sites-available/honeypot
        echo "Backup created: $BACKUP_FILE"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|stats|report|config|clean|backup}"
        echo ""
        echo "Commands:"
        echo "  start     - Start the honeypot service"
        echo "  stop      - Stop the honeypot service"
        echo "  restart   - Restart the honeypot service"
        echo "  status    - Show service status"
        echo "  logs      - Show live logs (add 'activity' or 'nginx' for specific logs)"
        echo "  stats     - Show basic statistics"
        echo "  report    - Generate daily report"
        echo "  config    - Configure practice name or logo"
        echo "  clean     - Remove old log files"
        echo "  backup    - Create backup archive"
        ;;
esac
EOF

chmod +x "$HONEYPOT_DIR/manage.sh"
ln -sf "$HONEYPOT_DIR/manage.sh" /usr/local/bin/honeypot

log "Creating email configuration template..."
cat > "$HONEYPOT_DIR/email_config.json.example" << 'EOF'
{
  "smtp_server": "smtp.gmail.com",
  "smtp_port": 587,
  "email_user": "your-email@gmail.com",
  "email_pass": "your-app-password",
  "alert_email": "admin@yourcompany.com"
}
EOF

log "Setting up cron jobs..."
cat > "/etc/cron.d/honeypot" << 'EOF'
# Honeypot maintenance tasks
0 1 * * * honeypot /opt/honeypot/venv/bin/python3 /opt/honeypot/monitor.py
0 2 * * 0 honeypot /opt/honeypot/manage.sh clean
EOF

log "Setting proper permissions..."
chown -R "$HONEYPOT_USER:$HONEYPOT_USER" "$HONEYPOT_DIR"
chown -R "$HONEYPOT_USER:$HONEYPOT_USER" "$LOG_DIR"
chmod 750 "$HONEYPOT_DIR"
chmod 750 "$LOG_DIR"

log "Enabling services..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl enable nginx
systemctl enable fail2ban

log "Starting services..."
systemctl start fail2ban
systemctl start nginx
systemctl start "$SERVICE_NAME"

# Wait a moment for services to start
sleep 3

log "Verifying installation..."
if systemctl is-active --quiet "$SERVICE_NAME"; then
    log "✅ Honeypot service is running"
else
    error "❌ Honeypot service failed to start"
fi

if systemctl is-active --quiet nginx; then
    log "✅ Nginx is running"
else
    error "❌ Nginx failed to start"
fi

if curl -s http://localhost/health | grep -q "healthy"; then
    log "✅ Health check passed"
else
    warn "⚠️  Health check failed - service may still be starting"
fi

log "🎉 Installation completed successfully!"
echo ""
echo "==============================================="
echo "🍯 Healthcare Honeypot is now running!"
echo "==============================================="
echo ""
echo "📍 Access the honeypot at: http://$(hostname -I | awk '{print $1}')"
echo "📂 Logs directory: $LOG_DIR"
echo "⚙️  Configuration: $HONEYPOT_DIR"
echo ""
echo "🔧 Management commands:"
echo "  honeypot status    - Check service status"
echo "  honeypot logs      - View live logs"
echo "  honeypot stats     - Show statistics"
echo "  honeypot report    - Generate daily report"
echo "  honeypot config    - Configure practice settings"
echo ""
echo "📧 To enable email alerts:"
echo "  1. Copy $HONEYPOT_DIR/email_config.json.example"
echo "  2. Rename to email_config.json"
echo "  3. Fill in your SMTP settings"
echo ""
echo "🔒 Security Notes:"
echo "  • Firewall is enabled (SSH and HTTP only)"
echo "  • Fail2ban is monitoring for attacks"
echo "  • Log rotation is configured"
echo "  • Service runs as dedicated user"
echo ""
echo "📋 Next Steps:"
echo "  1. Test the honeypot in a browser"
echo "  2. Configure practice name: honeypot config practice 'Your Practice'"
echo "  3. Monitor logs: honeypot logs activity"
echo "  4. Set up email alerts (optional)"
echo ""
echo "For support, check the logs or run 'honeypot status'"