from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory, abort
import sqlite3
import secrets
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from collections import Counter
import uuid
import requests

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Configure upload folder
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Custom filter for newline to <br> conversion
@app.template_filter('nl2br')
def nl2br_filter(text):
    if text is None:
        return ""
    return text.replace('\n', '<br>')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_size(file):
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    return file_size <= MAX_FILE_SIZE

# Database initialization and migration
def init_db():
    conn = sqlite3.connect('whistleblower.db')
    cursor = conn.cursor()
    
    # Create reports table with new fields
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tracking_code TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            priority TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            date_of_incident TEXT NOT NULL,
            location TEXT NOT NULL,
            department TEXT NOT NULL,
            attachment_filename TEXT,
            file_size INTEGER
        )
    ''')
    
    # Migration: add columns if missing
    cursor.execute("PRAGMA table_info(reports)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'date_of_incident' not in columns:
        cursor.execute('ALTER TABLE reports ADD COLUMN date_of_incident TEXT NOT NULL DEFAULT ""')
    if 'location' not in columns:
        cursor.execute('ALTER TABLE reports ADD COLUMN location TEXT NOT NULL DEFAULT ""')
    if 'department' not in columns:
        cursor.execute('ALTER TABLE reports ADD COLUMN department TEXT NOT NULL DEFAULT ""')
    if 'attachment_filename' not in columns:
        cursor.execute('ALTER TABLE reports ADD COLUMN attachment_filename TEXT')
    if 'file_size' not in columns:
        cursor.execute('ALTER TABLE reports ADD COLUMN file_size INTEGER DEFAULT 0')
    if 'lat' not in columns:
        cursor.execute('ALTER TABLE reports ADD COLUMN lat REAL')
    if 'lng' not in columns:
        cursor.execute('ALTER TABLE reports ADD COLUMN lng REAL')
    
    # Create admin table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create comments table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL,
            comment TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (report_id) REFERENCES reports (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def generate_tracking_code():
    """Generate a unique 8-character tracking code"""
    return secrets.token_hex(4).upper()

# Define categories with English and Swahili
CATEGORIES = [
    {"en": "Safety Violation in the Field", "sw": "Uvunjaji wa Usalama Kazini"},
    {"en": "Sexual Harassment", "sw": "Unyanyasaji wa Kijinsia"},
    {"en": "Suspected Child Labor", "sw": "Kazi ya Mtoto Inayoshukiwa"},
    {"en": "Drug and Substance Abuse", "sw": "Matumizi Mabaya ya Dawa na Madawa"},
    {"en": "Welfare and Housing Conditions", "sw": "Hali ya Ustawi na Makazi"},
    {"en": "Family and Domestic Issues Impacting Work", "sw": "Masuala ya Familia na Nyumbani Yanayoathiri Kazi"}
]

def get_categories(lang="en"):
    return [cat[lang] for cat in CATEGORIES]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit_report', methods=['GET', 'POST'])
def submit_report():
    lang = request.args.get('lang', 'en')
    categories = get_categories(lang)
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        category = request.form.get('category')
        priority = request.form.get('priority')
        date_of_incident = request.form.get('date_of_incident')
        location = request.form.get('location')
        department = request.form.get('department')
        
        if not all([title, description, category, priority, date_of_incident, location, department]):
            flash('All fields are required!', 'error')
            return render_template('submit_report.html', categories=categories, lang=lang)
        
        conn = sqlite3.connect('whistleblower.db')
        cursor = conn.cursor()
        
        # Check for duplicate report
        cursor.execute('''
            SELECT tracking_code FROM reports WHERE title = ? AND description = ? AND date_of_incident = ? AND location = ? AND department = ?
        ''', (title, description, date_of_incident, location, department))
        existing = cursor.fetchone()
        
        if existing:
            conn.close()
            flash('A report with the same details already exists. Please check your tracking code or contact admin for follow-up.', 'error')
            return render_template('submit_report.html', categories=categories, lang=lang)
        
        # Handle file upload
        attachment_filename = None
        file_size = 0
        if 'attachment' in request.files:
            file = request.files['attachment']
            if file and file.filename != '':
                if not allowed_file(file.filename):
                    conn.close()
                    flash(f'Invalid file type. Allowed types are: {", ".join(ALLOWED_EXTENSIONS)}', 'error')
                    return render_template('submit_report.html', categories=categories, lang=lang)
                
                if not validate_file_size(file):
                    conn.close()
                    flash('File size exceeds maximum allowed size (5MB)', 'error')
                    return render_template('submit_report.html', categories=categories, lang=lang)
                
                # Generate secure unique filename
                ext = secure_filename(file.filename).rsplit('.', 1)[1].lower()
                attachment_filename = f"{uuid.uuid4()}.{ext}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], attachment_filename)
                file.save(file_path)
                file_size = os.path.getsize(file_path)
        
        tracking_code = generate_tracking_code()
        try:
            # Dummy coordinates for Kenya (replace with real geocoding later)
            lat, lng = geocode_location(location)
            
            cursor.execute('''
                INSERT INTO reports (
                    tracking_code, title, description, category, priority, 
                    status, date_of_incident, location, department, 
                    attachment_filename, file_size, lat, lng
                ) VALUES (?, ?, ?, ?, ?, 'Pending', ?, ?, ?, ?, ?, ?, ?)
            ''', (
                tracking_code, title, description, category, priority,
                date_of_incident, location, department,
                attachment_filename, file_size, lat, lng
            ))
            
            # Get the report ID and add initial status comment
            report_id = cursor.lastrowid
            cursor.execute('INSERT INTO comments (report_id, comment, is_admin) VALUES (?, ?, FALSE)', 
                          (report_id, "Status changed from None to Pending"))
            conn.commit()
            
            return render_template('submit_success.html', 
                                tracking_code=tracking_code,
                                attachment_filename=attachment_filename)
        except sqlite3.IntegrityError as e:
            flash(f'Error submitting report: {str(e)}', 'error')
            # Clean up uploaded file if there was an error
            if attachment_filename:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], attachment_filename))
                except OSError:
                    pass
        finally:
            conn.close()
    
    return render_template('submit_report.html', categories=categories, lang=lang)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    # Security check to prevent directory traversal
    if '..' in filename or filename.startswith('/'):
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin/attachment/<filename>')
def serve_attachment(filename):
    """Serve attachment files for admin view - alias for uploaded_file with admin check"""
    if 'admin_id' not in session:
        abort(403)
    # Security check to prevent directory traversal
    if '..' in filename or filename.startswith('/'):
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/track_report', methods=['GET', 'POST'])
def track_report():
    if request.method == 'POST':
        tracking_code = request.form.get('tracking_code')
        
        if not tracking_code:
            flash('Please enter a tracking code!', 'error')
            return render_template('track_report.html')
        
        conn = sqlite3.connect('whistleblower.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT r.*, COUNT(c.id) as comment_count
            FROM reports r
            LEFT JOIN comments c ON r.id = c.report_id
            WHERE r.tracking_code = ?
            GROUP BY r.id
        ''', (tracking_code,))
        
        report = cursor.fetchone()
        
        if report:
            # Get comments for this report
            cursor.execute('''
                SELECT * FROM comments 
                WHERE report_id = ? 
                ORDER BY created_at ASC
            ''', (report[0],))
            comments = cursor.fetchall()
            
            conn.close()
            return render_template('track_report.html', report=report, comments=comments, tracking_code=tracking_code)
        else:
            conn.close()
            flash('No report found with this tracking code!', 'error')
    
    return render_template('track_report.html')

@app.route('/add_user_comment', methods=['POST'])
def add_user_comment():
    tracking_code = request.form.get('tracking_code')
    comment = request.form.get('comment')
    if not tracking_code or not comment:
        return jsonify({'error': 'Tracking code and comment are required.'}), 400
    conn = sqlite3.connect('whistleblower.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM reports WHERE tracking_code = ?', (tracking_code,))
    report = cursor.fetchone()
    if not report:
        conn.close()
        return jsonify({'error': 'Invalid tracking code.'}), 404
    report_id = report[0]
    # Prevent duplicate user comments
    cursor.execute('''SELECT comment FROM comments WHERE report_id = ? AND is_admin = 0 ORDER BY created_at DESC LIMIT 1''', (report_id,))
    last_comment = cursor.fetchone()
    if last_comment and last_comment[0].strip() == comment.strip():
        conn.close()
        return jsonify({'error': 'You cannot submit the same comment twice in a row.'}), 400
    cursor.execute('INSERT INTO comments (report_id, comment, is_admin) VALUES (?, ?, FALSE)', (report_id, comment))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect('whistleblower.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM admins WHERE username = ?', (username,))
        admin = cursor.fetchone()
        conn.close()
        
        if admin and check_password_hash(admin[2], password):
            session['admin_id'] = admin[0]
            session['admin_username'] = admin[1]
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials!', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    search_query = request.args.get('q', '').strip()
    conn = sqlite3.connect('whistleblower.db')
    cursor = conn.cursor()
    
    if search_query:
        like_query = f"%{search_query}%"
        cursor.execute('''
            SELECT r.*, COUNT(c.id) as comment_count
            FROM reports r
            LEFT JOIN comments c ON r.id = c.report_id
            WHERE r.title LIKE ? OR r.description LIKE ? OR r.tracking_code LIKE ?
            GROUP BY r.id
            ORDER BY r.created_at DESC
        ''', (like_query, like_query, like_query))
    else:
        cursor.execute('''
            SELECT r.*, COUNT(c.id) as comment_count
            FROM reports r
            LEFT JOIN comments c ON r.id = c.report_id
            GROUP BY r.id
            ORDER BY r.created_at DESC
        ''')
    reports = cursor.fetchall()
    
    # Statistics
    cursor.execute('SELECT COUNT(*) FROM reports')
    total_reports = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM reports WHERE status = "Pending"')
    pending_reports = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM reports WHERE status = "In Progress"')
    in_progress_reports = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM reports WHERE status = "Resolved"')
    resolved_reports = cursor.fetchone()[0]
    
    # Category statistics
    cursor.execute('SELECT category, COUNT(*) FROM reports GROUP BY category ORDER BY COUNT(*) DESC')
    category_stats = cursor.fetchall()
    
    # Priority statistics
    cursor.execute('SELECT priority, COUNT(*) FROM reports GROUP BY priority ORDER BY COUNT(*) DESC')
    priority_stats = cursor.fetchall()
    
    # Recent activity
    cursor.execute('''
        SELECT DATE(created_at) as date, COUNT(*) as count 
        FROM reports 
        WHERE created_at >= date('now', '-7 days')
        GROUP BY DATE(created_at)
        ORDER BY date
    ''')
    recent_activity = cursor.fetchall()
    
    # Response time metrics
    cursor.execute('''
        SELECT AVG(JULIANDAY(updated_at) - JULIANDAY(created_at)) as avg_response_days
        FROM reports 
        WHERE status = 'Resolved' AND updated_at != created_at
    ''')
    avg_response_result = cursor.fetchone()
    avg_response_days = avg_response_result[0] if avg_response_result[0] else 0
    
    # Today's reports
    cursor.execute('SELECT COUNT(*) FROM reports WHERE DATE(created_at) = DATE("now")')
    today_reports = cursor.fetchone()[0]
    
    # Reports requiring follow-up
    cursor.execute('''
        SELECT COUNT(*) FROM reports 
        WHERE status = "Pending" 
        AND JULIANDAY("now") - JULIANDAY(created_at) > 3
    ''')
    follow_up_reports = cursor.fetchone()[0]
    
    # SLA compliance
    cursor.execute('''
        SELECT COUNT(*) FROM reports 
        WHERE status = "Resolved" 
        AND JULIANDAY(updated_at) - JULIANDAY(created_at) <= 7
    ''')
    sla_compliant = cursor.fetchone()[0]
    
    sla_percentage = (sla_compliant / resolved_reports * 100) if resolved_reports > 0 else 0
    
    conn.close()
    
    return render_template('admin_dashboard.html', 
                         reports=reports, 
                         total_reports=total_reports,
                         pending_reports=pending_reports,
                         in_progress_reports=in_progress_reports,
                         resolved_reports=resolved_reports,
                         category_stats=category_stats,
                         priority_stats=priority_stats,
                         recent_activity=recent_activity,
                         avg_response_days=round(avg_response_days, 1),
                         today_reports=today_reports,
                         follow_up_reports=follow_up_reports,
                         sla_percentage=round(sla_percentage, 1))

@app.route('/admin/report/<int:report_id>')
def admin_view_report(report_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    conn = sqlite3.connect('whistleblower.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM reports WHERE id = ?', (report_id,))
    report = cursor.fetchone()
    
    if not report:
        conn.close()
        flash('Report not found!', 'error')
        return redirect(url_for('admin_dashboard'))
    
    cursor.execute('''
        SELECT * FROM comments 
        WHERE report_id = ? 
        ORDER BY created_at ASC
    ''', (report_id,))
    comments = cursor.fetchall()
    
    conn.close()
    
    return render_template('admin_view_report.html', report=report, comments=comments)

@app.route('/admin/update_status', methods=['POST'])
def update_status():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    report_id = request.form.get('report_id')
    new_status = request.form.get('status')
    
    conn = sqlite3.connect('whistleblower.db')
    cursor = conn.cursor()
    
    # Get current status before updating
    cursor.execute('SELECT status FROM reports WHERE id = ?', (report_id,))
    current_status = cursor.fetchone()[0]
    
    # Update the status
    cursor.execute('''
        UPDATE reports 
        SET status = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (new_status, report_id))
    
    # Add status change comment
    status_comment = f"Status changed from {current_status} to {new_status}"
    cursor.execute('''
        INSERT INTO comments (report_id, comment, is_admin)
        VALUES (?, ?, TRUE)
    ''', (report_id, status_comment))
    
    conn.commit()
    conn.close()
    
    flash(f'Status updated to {new_status}', 'success')
    return redirect(url_for('admin_view_report', report_id=report_id))

@app.route('/admin/add_comment', methods=['POST'])
def add_admin_comment():
    if 'admin_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    report_id = request.form.get('report_id')
    comment = request.form.get('comment')
    
    if not comment:
        return jsonify({'error': 'Comment is required'}), 400
    
    conn = sqlite3.connect('whistleblower.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO comments (report_id, comment, is_admin)
        VALUES (?, ?, TRUE)
    ''', (report_id, comment))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin/settings')
def admin_settings():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    return render_template('admin_settings.html')

@app.route('/admin/reports')
def admin_reports():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    conn = sqlite3.connect('whistleblower.db')
    cursor = conn.cursor()
    cursor.execute('SELECT category FROM reports')
    categories = [row[0] for row in cursor.fetchall()]
    category_counts = Counter(categories)
    category_data = {
        'labels': list(category_counts.keys()),
        'counts': list(category_counts.values())
    }
    cursor.execute('SELECT location, category FROM reports')
    locations = cursor.fetchall()
    location_data = []
    for loc, cat in locations:
        location_data.append({
            'location': loc,
            'category': cat,
            'lat': None,
            'lng': None
        })
    conn.close()
    return render_template('admin_reports.html', category_data=category_data, location_data=location_data)

@app.route('/admin/report_log')
def admin_report_log():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    return '<h1>Report Log (Coming Soon)</h1><p>This page will show a chronological log of all reports and actions.</p>'

@app.route('/admin/api/dashboard-data')
def dashboard_data():
    if 'admin_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect('whistleblower.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM reports')
    total_reports = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM reports WHERE status = "Pending"')
    pending_reports = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM reports WHERE status = "In Progress"')
    in_progress_reports = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM reports WHERE status = "Resolved"')
    resolved_reports = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM reports WHERE DATE(created_at) = DATE("now")')
    today_reports = cursor.fetchone()[0]
    
    cursor.execute('SELECT category, COUNT(*) FROM reports GROUP BY category ORDER BY COUNT(*) DESC')
    category_stats = cursor.fetchall()
    
    cursor.execute('''
        SELECT DATE(created_at) as date, COUNT(*) as count 
        FROM reports 
        WHERE created_at >= date('now', '-7 days')
        GROUP BY DATE(created_at)
        ORDER BY date
    ''')
    recent_activity = cursor.fetchall()
    
    cursor.execute('''
        SELECT r.*, COUNT(c.id) as comment_count
        FROM reports r
        LEFT JOIN comments c ON r.id = c.report_id
        GROUP BY r.id
        ORDER BY r.created_at DESC
        LIMIT 10
    ''')
    latest_reports = cursor.fetchall()
    
    conn.close()
    
    return jsonify({
        'total_reports': total_reports,
        'pending_reports': pending_reports,
        'in_progress_reports': in_progress_reports,
        'resolved_reports': resolved_reports,
        'today_reports': today_reports,
        'category_stats': category_stats,
        'recent_activity': recent_activity,
        'latest_reports': latest_reports
    })

@app.route('/admin/api/locations')
def admin_locations():
    if 'admin_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = sqlite3.connect('whistleblower.db')
    cursor = conn.cursor()
    cursor.execute('SELECT location, category, lat, lng FROM reports')
    locations = [
        {'location': row[0], 'category': row[1], 'lat': row[2], 'lng': row[3]}
        for row in cursor.fetchall()
    ]
    conn.close()
    return jsonify({'locations': locations})

@app.route('/setup_admin', methods=['GET', 'POST'])
def setup_admin():
    conn = sqlite3.connect('whistleblower.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM admins')
    admin_count = cursor.fetchone()[0]
    conn.close()
    
    if admin_count > 0:
        flash('Admin account already exists!', 'error')
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([username, password, confirm_password]):
            flash('All fields are required!', 'error')
            return render_template('setup_admin.html')
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('setup_admin.html')
        
        password_hash = generate_password_hash(password)
        
        conn = sqlite3.connect('whistleblower.db')
        cursor = conn.cursor()
        
        cursor.execute('INSERT INTO admins (username, password_hash) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        conn.close()
        
        flash('Admin account created successfully! You can now login.', 'success')
        return redirect(url_for('admin_login'))
    
    return render_template('setup_admin.html')

@app.route('/reset_admin_password', methods=['GET', 'POST'])
def reset_admin_password():
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([new_password, confirm_password]):
            flash('All fields are required!', 'error')
            return render_template('reset_admin_password.html')
        
        if new_password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('reset_admin_password.html')
        
        password_hash = generate_password_hash(new_password)
        
        conn = sqlite3.connect('whistleblower.db')
        cursor = conn.cursor()
        
        cursor.execute('UPDATE admins SET password_hash = ? WHERE id = 1', (password_hash,))
        conn.commit()
        conn.close()
        
        flash('Admin password reset successfully! You can now login with the new password.', 'success')
        return redirect(url_for('admin_login'))
    
    return render_template('reset_admin_password.html')

def geocode_location(location):
    """Geocode a location string using Nominatim (OpenStreetMap)"""
    try:
        url = "https://nominatim.openstreetmap.org/search"
        params = {
            "q": location + ", Kenya",
            "format": "json",
            "limit": 1
        }
        headers = {"User-Agent": "WhistleBlowerApp/1.0"}
        response = requests.get(url, params=params, headers=headers, timeout=5)
        data = response.json()
        if data and len(data) > 0:
            lat = float(data[0]['lat'])
            lng = float(data[0]['lon'])
            return lat, lng
    except Exception as e:
        print(f"Geocoding error: {e}")
    return None, None

if __name__ == '__main__':
    init_db()
    app.run(debug=True)