import os
import time
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import CSRFProtect
from flask_migrate import Migrate
from flask_mail import Mail, Message
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.security import generate_password_hash, check_password_hash
from w3bxAN import scan_sql_injection, scan_xss, remote_code_execution, security_misconfiguration, broken_auth, csrf_scan
import json
import plotly
import plotly.express as px
import pandas as pd

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-secret-key-for-development')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnerability_scanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Configure email settings
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', '')

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')
    scans = db.relationship('Scan', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    results = db.relationship('ScanResult', backref='scan', lazy=True)
    scheduled = db.Column(db.Boolean, default=False)
    schedule_interval = db.Column(db.String(50), nullable=True)
    last_run = db.Column(db.DateTime, nullable=True)
    next_run = db.Column(db.DateTime, nullable=True)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    vulnerability_type = db.Column(db.String(50), nullable=False)
    is_vulnerable = db.Column(db.Boolean, default=False)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    remediation = db.Column(db.Text, nullable=True)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.start()

# Helper function to run a scan
def run_scan(scan_id):
    scan = Scan.query.get(scan_id)
    if not scan:
        return
    
    scan.status = 'running'
    scan.last_run = datetime.utcnow()
    db.session.commit()
    
    url = scan.url
    results = {}
    
    # Capture output from scan functions
    class OutputCapture:
        def __init__(self):
            self.value = ""
        def write(self, string):
            self.value += string
        def flush(self):
            pass
    
    # SQL Injection scan
    sql_output = OutputCapture()
    import sys
    original_stdout = sys.stdout
    sys.stdout = sql_output
    sql_vulnerable = scan_sql_injection(url)
    sys.stdout = original_stdout
    
    # Store SQL Injection results
    sql_result = ScanResult(
        scan_id=scan.id,
        vulnerability_type='SQL Injection',
        is_vulnerable=True if 'SQL Injection vulnerability detected' in sql_output.value else False,
        details=sql_output.value,
        remediation="Update your system regularly and use parameterized queries."
    )
    db.session.add(sql_result)
    
    # XSS scan
    xss_output = OutputCapture()
    sys.stdout = xss_output
    xss_vulnerable = scan_xss(url)
    sys.stdout = original_stdout
    
    # Store XSS results
    xss_result = ScanResult(
        scan_id=scan.id,
        vulnerability_type='Cross-Site Scripting (XSS)',
        is_vulnerable=xss_vulnerable,
        details=xss_output.value,
        remediation="Use sanitization libraries and input validation techniques."
    )
    db.session.add(xss_result)
    
    # RCE scan
    rce_output = OutputCapture()
    sys.stdout = rce_output
    remote_code_execution(url)
    sys.stdout = original_stdout
    
    # Store RCE results
    rce_result = ScanResult(
        scan_id=scan.id,
        vulnerability_type='Remote Code Execution',
        is_vulnerable=True if 'Possible RCE vulnerability detected' in rce_output.value else False,
        details=rce_output.value,
        remediation="Use secure coding practices and input validation."
    )
    db.session.add(rce_result)
    
    # Security Misconfiguration scan
    misconfig_output = OutputCapture()
    sys.stdout = misconfig_output
    security_misconfiguration(url)
    sys.stdout = original_stdout
    
    # Store Security Misconfiguration results
    misconfig_result = ScanResult(
        scan_id=scan.id,
        vulnerability_type='Security Misconfiguration',
        is_vulnerable=True if 'Security Misconfiguration' in misconfig_output.value else False,
        details=misconfig_output.value,
        remediation="Use latest security frameworks and proper configuration."
    )
    db.session.add(misconfig_result)
    
    # Broken Authentication scan
    auth_output = OutputCapture()
    sys.stdout = auth_output
    broken_auth(url)
    sys.stdout = original_stdout
    
    # Store Broken Authentication results
    auth_result = ScanResult(
        scan_id=scan.id,
        vulnerability_type='Broken Authentication',
        is_vulnerable=True if 'Broken Authentication Detected' in auth_output.value else False,
        details=auth_output.value,
        remediation="Implement two-factor authentication and secure session management."
    )
    db.session.add(auth_result)
    
    # CSRF scan
    csrf_output = OutputCapture()
    sys.stdout = csrf_output
    csrf_scan(url)
    sys.stdout = original_stdout
    
    # Store CSRF results
    csrf_result = ScanResult(
        scan_id=scan.id,
        vulnerability_type='Cross-Site Request Forgery (CSRF)',
        is_vulnerable=True if 'CSRF Vulnerability Detected' in csrf_output.value else False,
        details=csrf_output.value,
        remediation="Use CAPTCHA or anti-CSRF tokens."
    )
    db.session.add(csrf_result)
    
    # Update scan status
    scan.status = 'completed'
    db.session.commit()
    
    # Send email notification if vulnerabilities found
    vulnerable_results = ScanResult.query.filter_by(scan_id=scan.id, is_vulnerable=True).all()
    if vulnerable_results and app.config['MAIL_USERNAME']:
        user = User.query.get(scan.user_id)
        if user and user.email:
            send_vulnerability_alert(user.email, scan, vulnerable_results)

# Function to send vulnerability alert emails
def send_vulnerability_alert(email, scan, vulnerabilities):
    subject = f"Vulnerability Alert: {scan.url}"
    body = f"Vulnerabilities were detected in your scan of {scan.url}:\n\n"
    
    for vuln in vulnerabilities:
        body += f"- {vuln.vulnerability_type}\n"
        body += f"  Remediation: {vuln.remediation}\n\n"
    
    body += f"\nPlease log in to view the full report: http://localhost:5000/scans/{scan.id}"
    
    msg = Message(subject=subject, recipients=[email], body=body)
    mail.send(msg)

# Schedule a scan
def schedule_scan(scan_id, interval):
    scan = Scan.query.get(scan_id)
    if not scan:
        return
    
    # Remove any existing job for this scan
    for job in scheduler.get_jobs():
        if job.id == f"scan_{scan_id}":
            job.remove()
    
    # Set up new schedule
    if interval == 'hourly':
        job = scheduler.add_job(run_scan, 'interval', hours=1, id=f"scan_{scan_id}", args=[scan_id])
        scan.next_run = datetime.now() + pd.Timedelta(hours=1)
    elif interval == 'daily':
        job = scheduler.add_job(run_scan, 'interval', days=1, id=f"scan_{scan_id}", args=[scan_id])
        scan.next_run = datetime.now() + pd.Timedelta(days=1)
    elif interval == 'weekly':
        job = scheduler.add_job(run_scan, 'interval', weeks=1, id=f"scan_{scan_id}", args=[scan_id])
        scan.next_run = datetime.now() + pd.Timedelta(weeks=1)
    
    scan.scheduled = True
    scan.schedule_interval = interval
    db.session.commit()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        
        flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user's scans
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.timestamp.desc()).all()
    
    # Get vulnerability statistics for charts
    scan_data = []
    for scan in scans:
        results = ScanResult.query.filter_by(scan_id=scan.id).all()
        vulnerable_count = sum(1 for r in results if r.is_vulnerable)
        scan_data.append({
            'id': scan.id,
            'url': scan.url,
            'date': scan.timestamp.strftime('%Y-%m-%d'),
            'vulnerable_count': vulnerable_count,
            'total_count': len(results)
        })
    
    # Create chart data
    if scan_data:
        df = pd.DataFrame(scan_data)
        fig = px.bar(df, x='url', y='vulnerable_count', title='Vulnerabilities by URL')
        chart_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    else:
        chart_json = None
    
    return render_template('dashboard.html', scans=scans, chart_json=chart_json)

@app.route('/new_scan', methods=['GET', 'POST'])
@login_required
def new_scan():
    if request.method == 'POST':
        url = request.form.get('url')
        
        # Create new scan
        scan = Scan(url=url, user_id=current_user.id)
        db.session.add(scan)
        db.session.commit()
        
        # Run scan immediately if requested
        if 'run_now' in request.form:
            run_scan(scan.id)
        
        # Schedule scan if requested
        if 'schedule' in request.form:
            interval = request.form.get('interval')
            schedule_scan(scan.id, interval)
        
        flash('Scan created successfully')
        return redirect(url_for('dashboard'))
    
    return render_template('new_scan.html')

@app.route('/scans/<int:scan_id>')
@login_required
def view_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure user owns this scan
    if scan.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to view this scan')
        return redirect(url_for('dashboard'))
    
    results = ScanResult.query.filter_by(scan_id=scan.id).all()
    
    # Prepare data for vulnerability chart
    vuln_types = [r.vulnerability_type for r in results]
    vuln_status = ['Vulnerable' if r.is_vulnerable else 'Secure' for r in results]
    
    df = pd.DataFrame({
        'Vulnerability Type': vuln_types,
        'Status': vuln_status
    })
    
    fig = px.pie(df, names='Vulnerability Type', color='Status',
                 color_discrete_map={'Vulnerable': 'red', 'Secure': 'green'},
                 title='Vulnerability Assessment')
    chart_json = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    
    return render_template('view_scan.html', scan=scan, results=results, chart_json=chart_json)

@app.route('/run_scan/<int:scan_id>')
@login_required
def trigger_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure user owns this scan
    if scan.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to run this scan')
        return redirect(url_for('dashboard'))
    
    run_scan(scan.id)
    flash('Scan started successfully')
    return redirect(url_for('view_scan', scan_id=scan.id))

@app.route('/schedule_scan/<int:scan_id>', methods=['POST'])
@login_required
def update_schedule(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure user owns this scan
    if scan.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to schedule this scan')
        return redirect(url_for('dashboard'))
    
    interval = request.form.get('interval')
    if interval in ['hourly', 'daily', 'weekly']:
        schedule_scan(scan.id, interval)
        flash(f'Scan scheduled to run {interval}')
    else:
        # Cancel scheduling
        for job in scheduler.get_jobs():
            if job.id == f"scan_{scan.id}":
                job.remove()
        
        scan.scheduled = False
        scan.schedule_interval = None
        scan.next_run = None
        db.session.commit()
        flash('Scan schedule cancelled')
    
    return redirect(url_for('view_scan', scan_id=scan.id))

@app.route('/admin')
@login_required
def admin():
    # Ensure user is admin
    if current_user.role != 'admin':
        flash('You do not have permission to access the admin panel')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    scans = Scan.query.all()
    
    return render_template('admin.html', users=users, scans=scans)

@app.route('/api/scan_status/<int:scan_id>')
@login_required
def scan_status(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    
    # Ensure user owns this scan
    if scan.user_id != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify({
        'status': scan.status,
        'last_run': scan.last_run.isoformat() if scan.last_run else None,
        'next_run': scan.next_run.isoformat() if scan.next_run else None
    })

# Create database tables
with app.app_context():
    db.create_all()
    
    # Create admin user if it doesn't exist
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', email='admin@example.com', role='admin')
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)