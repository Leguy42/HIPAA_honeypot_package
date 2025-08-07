#!/bin/bash
# deploy_practice_mgmt.sh - Practice Management System Honeypot Deployment
# Run with: sudo ./deploy_practice_mgmt.sh

set -e

echo "🏥 Practice Management System Honeypot Deployment"
echo "================================================="

# Configuration
HONEYPOT_USER="honeypot"
HONEYPOT_DIR="/opt/practice-mgmt"
LOG_DIR="/var/log/honeypot"
SERVICE_NAME="practice-management"
PORT=8080

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

log "Creating practice management honeypot directory structure..."
mkdir -p "$HONEYPOT_DIR"
mkdir -p "$LOG_DIR"
chown -R "$HONEYPOT_USER:$HONEYPOT_USER" "$HONEYPOT_DIR"
chown -R "$HONEYPOT_USER:$HONEYPOT_USER" "$LOG_DIR"

log "Setting up Python virtual environment..."
sudo -u "$HONEYPOT_USER" python3 -m venv "$HONEYPOT_DIR/venv"
sudo -u "$HONEYPOT_USER" "$HONEYPOT_DIR/venv/bin/pip" install --upgrade pip
sudo -u "$HONEYPOT_USER" "$HONEYPOT_DIR/venv/bin/pip" install flask gunicorn

log "Creating practice management application..."
cat > "$HONEYPOT_DIR/app.py" << 'EOF'
# [The Practice Management Python code would go here - copy from the previous artifact]
# This is truncated for space, but you would copy the complete code
EOF

log "Creating Gunicorn configuration for practice management..."
cat > "$HONEYPOT_DIR/gunicorn.conf.py" << EOF
# Gunicorn configuration for practice management system
bind = "127.0.0.1:$PORT"
workers = 2
worker_class = "sync"
worker_connections = 500
max_requests = 1000
max_requests_jitter = 100
timeout = 30
keepalive = 2
preload_app = True
user = "$HONEYPOT_USER"
group = "$HONEYPOT_USER"
pid = "/var/run/honeypot/practice-mgmt.pid"
access_log = "$LOG_DIR/practice_mgmt_access.log"
error_log = "$LOG_DIR/practice_mgmt_error.log"
log_level = "info"
EOF

log "Creating systemd service for practice management..."
cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=Healthcare Practice Management System Honeypot
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

log "Creating nginx configuration for practice management..."
cat > "/etc/nginx/sites-available/practice-mgmt" << EOF
server {
    listen 8080;
    server_name _;
    
    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Hide nginx version
    server_tokens off;
    
    # Rate limiting for admin interface
    limit_req_zone \$binary_remote_addr zone=practice_mgmt:10m rate=20r/m;
    limit_req zone=practice_mgmt burst=50 nodelay;
    
    # Logging
    access_log $LOG_DIR/practice_mgmt_nginx_access.log;
    error_log $LOG_DIR/practice_mgmt_nginx_error.log;
    
    location / {
        proxy_pass http://127.0.0.1:$PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Timeouts
        proxy_connect_timeout 10s;
        proxy_send_timeout 15s;
        proxy_read_timeout 15s;
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        proxy_pass http://127.0.0.1:$PORT/health;
    }
}
EOF

log "Enabling practice management nginx site..."
ln -sf /etc/nginx/sites-available/practice-mgmt /etc/nginx/sites-enabled/

log "Updating firewall for practice management..."
ufw allow 8080/tcp comment "HTTP - Practice Management Honeypot"

log "Creating practice management monitoring script..."
cat > "$HONEYPOT_DIR/monitor_practice.py" << 'EOF'
#!/usr/bin/env python3
"""
Practice Management specific monitoring script
Analyzes staff login attempts and administrative access
"""

import json
import os
from datetime import datetime, timedelta
from collections import defaultdict

LOG_DIR = "/var/log/honeypot"
CRITICAL_ENDPOINTS = ['/admin', '/backup', '/api/financial']
STAFF_ROLES = ['physician', 'nurse', 'admin', 'receptionist', 'billing']

def analyze_practice_logs(date_str):
    """Analyze practice management specific activities"""
    log_file = os.path.join(LOG_DIR, f"practice_mgmt_{date_str}.json")
    
    if not os.path.exists(log_file):
        return None
        
    activities = []
    with open(log_file, 'r') as f:
        for line in f:
            try:
                activities.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue
    
    if not activities:
        return None
    
    analysis = {
        'total_activities': len(activities),
        'staff_login_attempts': 0,
        'role_breakdown': defaultdict(int),
        'critical_access_attempts': 0,
        'suspicious_ips': set(),
        'admin_panel_access': 0,
        'financial_data_access': 0,
        'unique_usernames': set(),
        'failed_authentications': 0
    }
    
    for activity in activities:
        action = activity.get('action', '')
        data = activity.get('data', {})
        client_ip = activity.get('client_ip', '')
        
        # Track staff login attempts
        if action == 'staff_login_attempt':
            analysis['staff_login_attempts'] += 1
            role = data.get('role', 'unknown')
            analysis['role_breakdown'][role] += 1
            analysis['unique_usernames'].add(data.get('username', ''))
        
        # Track critical endpoint access
        if 'admin_panel_access' in action:
            analysis['admin_panel_access'] += 1
            analysis['suspicious_ips'].add(client_ip)
            
        if 'financial_data_access' in action:
            analysis['financial_data_access'] += 1
            analysis['suspicious_ips'].add(client_ip)
            
        if data.get('alert_level') in ['HIGH', 'CRITICAL']:
            analysis['critical_access_attempts'] += 1
            analysis['suspicious_ips'].add(client_ip)
    
    # Convert sets to lists for JSON serialization
    analysis['suspicious_ips'] = list(analysis['suspicious_ips'])
    analysis['unique_usernames'] = list(analysis['unique_usernames'])
    analysis['role_breakdown'] = dict(analysis['role_breakdown'])
    
    return analysis

def generate_practice_report(date_str):
    """Generate practice management security report"""
    analysis = analyze_practice_logs(date_str)
    
    if not analysis:
        print(f"No practice management activity found for {date_str}")
        return
    
    print(f"\n🏥 Practice Management Security Report - {date_str}")
    print("=" * 60)
    print(f"Total Activities: {analysis['total_activities']}")
    print(f"Staff Login Attempts: {analysis['staff_login_attempts']}")
    print(f"Unique Usernames Tried: {len(analysis['unique_usernames'])}")
    print(f"Admin Panel Access Attempts: {analysis['admin_panel_access']}")
    print(f"Financial Data Access Attempts: {analysis['financial_data_access']}")
    print(f"Critical Security Events: {analysis['critical_access_attempts']}")
    print(f"Suspicious IP Addresses: {len(analysis['suspicious_ips'])}")
    
    print("\nRole-based Login Attempts:")
    for role, count in analysis['role_breakdown'].items():
        print(f"  {role.capitalize()}: {count}")
    
    if analysis['suspicious_ips']:
        print("\nSuspicious IP Addresses:")
        for ip in analysis['suspicious_ips'][:10]:  # Show top 10
            print(f"  {ip}")
    
    # Security alerts
    alerts = []
    if analysis['admin_panel_access'] > 0:
        alerts.append(f"⚠️  {analysis['admin_panel_access']} admin panel access attempts detected!")
    
    if analysis['financial_data_access'] > 0:
        alerts.append(f"💰 {analysis['financial_data_access']} financial data access attempts!")
    
    if len(analysis['suspicious_ips']) > 5:
        alerts.append(f"🚨 High number of suspicious IPs: {len(analysis['suspicious_ips'])}")
    
    if alerts:
        print("\n🚨 SECURITY ALERTS:")
        for alert in alerts:
            print(f"  {alert}")
    
    # Save detailed report
    report_file = os.path.join(LOG_DIR, f"practice_mgmt_report_{date_str}.json")
    with open(report_file, 'w') as f:
        json.dump({
            'date': date_str,
            'analysis': analysis,
            'alerts': alerts,
            'generated_at': datetime.now().isoformat()
        }, f, indent=2)
    
    print(f"\nDetailed report saved to: {report_file}")

if __name__ == "__main__":
    # Generate report for yesterday
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y%m%d')
    generate_practice_report(yesterday)
EOF

chmod +x "$HONEYPOT_DIR/monitor_practice.py"

log "Creating practice management control script..."
cat > "$HONEYPOT_DIR/practice_control.sh" << 'EOF'
#!/bin/bash
# Practice Management System Control Script

HONEYPOT_DIR="/opt/practice-mgmt"
LOG_DIR="/var/log/honeypot"
SERVICE_NAME="practice-management"

case "$1" in
    start)
        echo "Starting Practice Management System..."
        systemctl start $SERVICE_NAME
        systemctl status $SERVICE_NAME --no-pager
        ;;
    stop)
        echo "Stopping Practice Management System..."
        systemctl stop $SERVICE_NAME
        ;;
    restart)
        echo "Restarting Practice Management System..."
        systemctl restart $SERVICE_NAME
        systemctl restart nginx
        ;;
    status)
        systemctl status $SERVICE_NAME --no-pager
        echo ""
        echo "Recent Activity:"
        tail -5 $LOG_DIR/practice_mgmt.log 2>/dev/null || echo "No recent activity"
        ;;
    logs)
        case "$2" in
            activity)
                tail -f $LOG_DIR/practice_mgmt_$(date +%Y%m%d).json 2>/dev/null || \
                echo "No activity log found for today"
                ;;
            nginx)
                tail -f $LOG_DIR/practice_mgmt_nginx_access.log
                ;;
            error)
                tail -f $LOG_DIR/practice_mgmt_error.log
                ;;
            *)
                tail -f $LOG_DIR/practice_mgmt.log
                ;;
        esac
        ;;
    report)
        python3 $HONEYPOT_DIR/monitor_practice.py
        ;;
    stats)
        echo "=== Practice Management Statistics ==="
        echo "Service Status: $(systemctl is-active $SERVICE_NAME)"
        echo ""
        
        if [ -f "$LOG_DIR/practice_mgmt_$(date +%Y%m%d).json" ]; then
            echo "Today's Activity:"
            echo "  Staff Login Attempts: $(grep -c "staff_login_attempt" "$LOG_DIR/practice_mgmt_$(date +%Y%m%d).json" 2>/dev/null || echo 0)"
            echo "  Admin Access Attempts: $(grep -c "admin_panel_access" "$LOG_DIR/practice_mgmt_$(date +%Y%m%d).json" 2>/dev/null || echo 0)"
            echo "  Unique IPs: $(grep -o '"client_ip":"[^"]*"' "$LOG_DIR/practice_mgmt_$(date +%Y%m%d).json" 2>/dev/null | sort -u | wc -l || echo 0)"
        else
            echo "No activity recorded today"
        fi
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
    test)
        echo "Testing Practice Management System..."
        if curl -s http://localhost:8080/health | grep -q "healthy"; then
            echo "✅ Health check passed"
        else
            echo "❌ Health check failed"
        fi
        
        echo "Testing critical endpoints (for monitoring):"
        curl -s -o /dev/null -w "Admin panel: %{http_code}\n" http://localhost:8080/admin
        curl -s -o /dev/null -w "Backup endpoint: %{http_code}\n" http://localhost:8080/backup
        curl -s -o /dev/null -w "Financial API: %{http_code}\n" http://localhost:8080/api/financial
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|report|stats|config|test}"
        echo ""
        echo "Commands:"
        echo "  start     - Start the practice management system"
        echo "  stop      - Stop the practice management system"
        echo "  restart   - Restart the practice management system"
        echo "  status    - Show service status and recent activity"
        echo "  logs      - Show live logs (add 'activity', 'nginx', or 'error')"
        echo "  report    - Generate security analysis report"
        echo "  stats     - Show basic statistics"
        echo "  config    - Configure practice name or logo"
        echo "  test      - Test system health and endpoints"
        ;;
esac
EOF

chmod +x "$HONEYPOT_DIR/practice_control.sh"
ln -sf "$HONEYPOT_DIR/practice_control.sh" /usr/local/bin/practice-mgmt

log "Updating log rotation for practice management..."
cat >> "/etc/logrotate.d/honeypot" << 'EOF'

/var/log/honeypot/practice_mgmt*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 honeypot honeypot
    postrotate
        systemctl reload practice-management
    endscript
}
EOF

log "Setting up cron job for practice management monitoring..."
cat >> "/etc/cron.d/honeypot" << 'EOF'
# Practice Management monitoring
15 1 * * * honeypot /opt/practice-mgmt/venv/bin/python3 /opt/practice-mgmt/monitor_practice.py
EOF

log "Setting proper permissions..."
chown -R "$HONEYPOT_USER:$HONEYPOT_USER" "$HONEYPOT_DIR"
chmod 750 "$HONEYPOT_DIR"

log "Enabling and starting services..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

# Test nginx configuration
nginx -t

# Reload nginx to pick up new site
systemctl reload nginx

# Wait for service to start
sleep 5

log "Verifying installation..."
if systemctl is-active --quiet "$SERVICE_NAME"; then
    log "✅ Practice Management service is running"
else
    error "❌ Practice Management service failed to start"
fi

if curl -s http://localhost:8080/health | grep -q "healthy"; then
    log "✅ Practice Management health check passed"
else
    warn "⚠️  Health check failed - service may still be starting"
fi

log "🎉 Practice Management System deployment completed!"
echo ""
echo "=========================================================="
echo "🏥 Practice Management System Honeypot is now running!"
echo "=========================================================="
echo ""
echo "📍 Access the system at: http://$(hostname -I | awk '{print $1}'):8080"
echo "📂 Logs directory: $LOG_DIR"
echo "⚙️  Configuration: $HONEYPOT_DIR"
echo ""
echo "🔧 Management commands:"
echo "  practice-mgmt status    - Check service status"
echo "  practice-mgmt logs      - View live logs"
echo "  practice-mgmt report    - Generate security report"
echo "  practice-mgmt stats     - Show activity statistics"
echo "  practice-mgmt test      - Test critical endpoints"
echo ""
echo "🎯 High-Value Honeypot Targets:"
echo "  • Staff login page (multiple roles)"
echo "  • Admin panel (/admin)"
echo "  • Financial data API (/api/financial)"
echo "  • Backup endpoint (/backup)"
echo "  • Patient records access"
echo ""
echo "🔒 Security Monitoring:"
echo "  • All staff login attempts logged"
echo "  • Administrative access attempts flagged"
echo "  • Financial data access triggers alerts"
echo "  • Role-based activity analysis"
echo "  • Suspicious IP tracking"
echo ""
echo "📊 What Gets Logged:"
echo "  • Username/role combinations tried"
echo "  • Admin panel access attempts (CRITICAL)"
echo "  • Financial API calls (HIGH ALERT)"
echo "  • Patient data access patterns"
echo "  • Copy/paste attempts (data exfiltration)"
echo "  • Developer tools usage detection"
echo ""
echo "🔧 Customization:"
echo "  practice-mgmt config practice 'Your Practice Name'"
echo "  practice-mgmt config logo 'YP'"
echo ""
echo "📈 Combined with Patient Portal:"
echo "  Patient Portal: http://$(hostname -I | awk '{print $1}'):80"
echo "  Practice Mgmt:  http://$(hostname -I | awk '{print $1}'):8080"
echo ""
echo "This creates a realistic healthcare environment that will"
echo "attract attackers targeting both patient-facing and"
echo "administrative healthcare systems."