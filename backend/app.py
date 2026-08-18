from flask import Flask, request, jsonify, Response, session
from flask_cors import CORS
import config, db, ad, systems
import csv, io

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
CORS(app, supports_credentials=True, origins='*')

# ── AUTH ──────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def login():
    data       = request.get_json()
    username   = data.get('username', '')
    password   = data.get('password', '')
    ip_address = request.remote_addr

    result = db.check_or_create_user(username, password, ip_address)

    if result['success']:
        session['user'] = username
        session['role'] = result['role']
        return jsonify({
            'success':   True,
            'token':     'demo-token',
            'username':  result['username'],
            'full_name': result['full_name'],
            'role':      result['role'],
            'new_user':  False
        })
    
    # ← message ke hisaab se alag response
    return jsonify({
        'success': False,
        'message': result.get('message', 'invalid')
    }), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    data     = request.get_json() or {}
    username = session.get('user', data.get('username', ''))
    ip       = request.remote_addr

    if username:
        conn = db.get_connection()
        cur  = conn.cursor(dictionary=True)

        # Department dhundho
        cur.execute("SELECT dept FROM ad_users WHERE username=%s", (username,))
        ad_user = cur.fetchone()
        dept = ad_user['dept'] if ad_user else 'IT'
        system_name = f"PC-{dept}-{ip.split('.')[-1]}"

        # System logins mein LOGOUT entry daalo
        cur.execute("""
            INSERT INTO system_logins
            (timestamp, system_name, ip_address, username,
             department, event, duration, note)
            VALUES (NOW(), %s, %s, %s, %s, 'LOGOUT', '—', 'Portal logout')
        """, (system_name, ip, username, dept))

        conn.commit()
        conn.close()

    session.clear()
    return jsonify({'success': True})
# ── FIREWALL ──────────────────────────────────────────
@app.route('/api/stats')
def stats():
    return jsonify(db.get_stats())

@app.route('/api/logs')
def logs():
    return jsonify(db.get_logs(
        ip          = request.args.get('ip', ''),
        action      = request.args.get('action', ''),
        date_filter = request.args.get('date', ''),
        page        = int(request.args.get('page', 1))
    ))

@app.route('/api/logs/export')
def export_logs():
    logs_data = db.get_all_logs()
    output    = io.StringIO()
    writer    = csv.writer(output)
    writer.writerow(['Timestamp','Source IP','Dest IP','Port','Protocol','Action'])
    for log in logs_data:
        writer.writerow([log['timestamp'], log['src_ip'], log['dst_ip'],
                         log['port'], log['protocol'], log['action']])
    output.seek(0)
    return Response(output, mimetype='text/csv',
                    headers={'Content-Disposition':'attachment;filename=firelog.csv'})

@app.route('/api/reports')
def reports():
    return jsonify(db.get_reports())

# ── ACTIVE DIRECTORY ──────────────────────────────────
# ── ACTIVE DIRECTORY ──────────────────────────────────
@app.route('/api/ad/users', methods=['GET'])
def ad_users():
    return jsonify(db.get_ad_users(
        search = request.args.get('search', ''),
        dept   = request.args.get('dept', ''),
        status = request.args.get('status', '')
    ))

@app.route('/api/ad/users', methods=['POST'])
def ad_create_user():
    db.create_ad_user(request.get_json())
    return jsonify({'success': True}), 201

@app.route('/api/ad/users/<int:user_id>', methods=['PUT'])
def ad_update_user(user_id):
    db.update_ad_user(user_id, request.get_json())
    return jsonify({'success': True})

@app.route('/api/ad/users/<int:user_id>', methods=['DELETE'])
def ad_delete_user(user_id):
    db.delete_ad_user(user_id)
    return jsonify({'success': True})

@app.route('/api/ad/users/<int:user_id>/togglelock', methods=['POST'])
def ad_toggle_lock(user_id):
    db.toggle_ad_lock(user_id)
    return jsonify({'success': True})

@app.route('/api/ad/stats')
def ad_stats():
    return jsonify(db.get_ad_stats())

# ── AD Groups & OUs ───────────────────────────────────
@app.route('/api/ad/groups', methods=['GET'])
def ad_groups():
    db.update_group_members_count()  # ← refresh counts before returning
    return jsonify({
        'groups': db.get_groups(),
        'ous':    db.get_ous()
    })

@app.route('/api/ad/groups', methods=['POST'])
def create_group():
    db.create_group(request.get_json())
    return jsonify({'success': True}), 201

@app.route('/api/ad/groups/<string:name>', methods=['DELETE'])
def delete_group(name):
    db.delete_group(name)
    return jsonify({'success': True})

@app.route('/api/ad/ous', methods=['POST'])
def create_ou():
    db.create_ou(request.get_json())
    return jsonify({'success': True}), 201

@app.route('/api/ad/ous/<string:name>', methods=['DELETE'])
def delete_ou(name):
    db.delete_ou(name)
    return jsonify({'success': True})

@app.route('/api/ad/audit')
def ad_audit():
    return jsonify(db.get_audit_logs(
        action      = request.args.get('action', ''),
        date_filter = request.args.get('date', '')
    ))

# ── SYSTEMS ───────────────────────────────────────────
@app.route('/api/systems')
def get_systems():
    return jsonify(systems.get_systems())

@app.route('/api/system-logs')
def get_system_logs():
    return jsonify(systems.get_system_logs(
        system      = request.args.get('system', ''),
        user        = request.args.get('user', ''),
        event       = request.args.get('event', ''),
        date_filter = request.args.get('date', ''),
        page        = int(request.args.get('page', 1))
    ))

# ── PORTAL USERS ──────────────────────────────────────
@app.route('/api/portal-users', methods=['GET'])
def get_portal_users():
    return jsonify(db.get_portal_users())

@app.route('/api/portal-users/<int:user_id>', methods=['PUT'])
def update_portal_user(user_id):
    data = request.get_json()
    db.update_user_role(user_id, data['role'], data['status'])
    return jsonify({'success': True})

@app.route('/api/portal-users/<int:user_id>', methods=['DELETE'])
def delete_portal_user(user_id):
    db.delete_portal_user(user_id)
    return jsonify({'success': True})

# ── LOGIN HISTORY ─────────────────────────────────────
@app.route('/api/login-history')
def login_history():
    return jsonify(db.get_login_history(
        username = request.args.get('username', ''),
        status   = request.args.get('status', ''),
        page     = int(request.args.get('page', 1))
    ))
@app.route('/api/ad/users/<int:user_id>/reset-password', methods=['POST'])
def reset_ad_password(user_id):
    data = request.get_json()
    new_password = data.get('password', '')
    if not new_password:
        return jsonify({'success': False, 'message': 'Password required'}), 400
    db.reset_ad_user_password(user_id, new_password)
    return jsonify({'success': True})  
import os
import threat_parser

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

import os
import threat_parser

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── THREAT INTELLIGENCE ───────────────────────────────
@app.route('/api/threat/upload', methods=['POST'])
def upload_threat_pdf():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file'}), 400
    file     = request.files['file']
    if not file.filename.endswith('.pdf'):
        return jsonify({'success': False, 'message': 'PDF only'}), 400
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    try:
        ip_data, hash_data = threat_parser.parse_threat_pdf(filepath)
        ip_count, hash_count = threat_parser.save_to_db(
            ip_data, hash_data, file.filename,
            session.get('user', 'admin'), db
        )
        return jsonify({
            'success':    True,
            'ip_count':   ip_count,
            'hash_count': hash_count,
            'message':    f'{ip_count} IPs aur {hash_count} hashes extracted!'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/threat/stats')
def threat_stats():
    conn = db.get_connection()
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT COUNT(*) as total FROM threat_ips")
    total = cur.fetchone()['total']
    cur.execute("SELECT COUNT(*) as c FROM threat_ips WHERE severity='Very High'")
    very_high = cur.fetchone()['c']
    cur.execute("SELECT COUNT(*) as c FROM threat_ips WHERE severity='High'")
    high = cur.fetchone()['c']
    cur.execute("SELECT COUNT(*) as c FROM threat_ips WHERE severity='Medium'")
    medium = cur.fetchone()['c']
    cur.execute("SELECT COUNT(*) as c FROM threat_ips WHERE severity='Low'")
    low = cur.fetchone()['c']
    cur.execute("SELECT COUNT(*) as total FROM threat_hashes")
    hashes = cur.fetchone()['total']
    conn.close()
    return jsonify({
        'total': total, 'very_high': very_high,
        'high': high, 'medium': medium,
        'low': low, 'hashes': hashes
    })

@app.route('/api/threat/ips')
def get_threat_ips():
    severity = request.args.get('severity', '')
    search   = request.args.get('search', '')
    page     = int(request.args.get('page', 1))
    per_page = 20
    conn     = db.get_connection()
    cur      = conn.cursor(dictionary=True)
    query    = "SELECT * FROM threat_ips WHERE 1=1"
    params   = []
    if severity:
        query += " AND severity=%s"
        params.append(severity)
    if search:
        query += " AND ip_address LIKE %s"
        params.append(f"%{search}%")
    count_query = query.replace("SELECT *", "SELECT COUNT(*) as total")
    cur.execute(count_query, params)
    total = cur.fetchone()['total']
    query += " ORDER BY s_no ASC LIMIT %s OFFSET %s"
    params.extend([per_page, (page-1)*per_page])
    cur.execute(query, params)
    ips = cur.fetchall()
    for ip in ips:
        ip['uploaded_at'] = str(ip['uploaded_at'])
    conn.close()
    return jsonify({
        'ips': ips, 'total': total,
        'total_pages': max(1,(total+per_page-1)//per_page),
        'current_page': page
    })

@app.route('/api/threat/hashes')
def get_threat_hashes():
    conn = db.get_connection()
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM threat_hashes ORDER BY s_no")
    hashes = cur.fetchall()
    for h in hashes:
        h['uploaded_at'] = str(h['uploaded_at'])
    conn.close()
    return jsonify(hashes)

@app.route('/api/threat/match-firewall')
def match_threat_firewall():
    conn = db.get_connection()
    cur  = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT f.src_ip, f.timestamp, f.action, f.port,
               t.severity, t.events
        FROM firewall_logs f
        INNER JOIN threat_ips t ON f.src_ip = t.ip_address
        ORDER BY f.timestamp DESC
        LIMIT 50
    """)
    matches = cur.fetchall()
    for m in matches:
        m['timestamp'] = str(m['timestamp'])
    conn.close()
    return jsonify(matches)
# ── LOGIN IP THREATS ──────────────────────────────────
@app.route('/api/login-ip-threats')
def login_ip_threats():
    return jsonify(db.get_login_ip_threats(
        page = int(request.args.get('page', 1))
    ))

@app.route('/api/login-ip-threat-stats')
def login_ip_threat_stats():
    return jsonify(db.get_login_ip_threat_stats())
# ── RUN ───────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=config.DEBUG, port=config.PORT)
