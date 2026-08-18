import mysql.connector
from datetime import date
import config

def get_connection():
    return mysql.connector.connect(
        host     = config.DB_HOST,
        user     = config.DB_USER,
        password = config.DB_PASSWORD,
        database = config.DB_NAME
    )

def get_stats():
    conn  = get_connection()
    cur   = conn.cursor(dictionary=True)
    today = date.today().strftime('%Y-%m-%d')

    cur.execute("SELECT COUNT(*) as total FROM firewall_logs WHERE DATE(timestamp)=%s", (today,))
    total = cur.fetchone()['total']

    cur.execute("SELECT COUNT(*) as c FROM firewall_logs WHERE action='DENY' AND DATE(timestamp)=%s", (today,))
    blocked = cur.fetchone()['c']

    cur.execute("SELECT COUNT(*) as c FROM firewall_logs WHERE action='ALLOW' AND DATE(timestamp)=%s", (today,))
    allowed = cur.fetchone()['c']

    cur.execute("SELECT COUNT(DISTINCT src_ip) as c FROM firewall_logs WHERE DATE(timestamp)=%s", (today,))
    unique_ips = cur.fetchone()['c']

    cur.execute("""
        SELECT HOUR(timestamp) as hour, COUNT(*) as count
        FROM firewall_logs WHERE DATE(timestamp)=%s
        GROUP BY HOUR(timestamp) ORDER BY hour
    """, (today,))
    hourly = cur.fetchall()
    hours  = [f"{str(r['hour']).zfill(2)}:00" for r in hourly]
    counts = [r['count'] for r in hourly]

    conn.close()
    return {
        'total': total, 'blocked': blocked,
        'allowed': allowed, 'unique_ips': unique_ips,
        'hours': hours, 'counts': counts
    }

def get_logs(ip='', action='', date_filter='', page=1, per_page=10):
    conn   = get_connection()
    cur    = conn.cursor(dictionary=True)
    offset = (page - 1) * per_page
    query  = "SELECT * FROM firewall_logs WHERE 1=1"
    params = []

    if ip:
        query += " AND src_ip LIKE %s"
        params.append(f"%{ip}%")
    if action:
        query += " AND action=%s"
        params.append(action)
    if date_filter:
        query += " AND DATE(timestamp)=%s"
        params.append(date_filter)

    count_query = query.replace("SELECT *", "SELECT COUNT(*) as total")
    cur.execute(count_query, params)
    total = cur.fetchone()['total']

    query += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
    params.extend([per_page, offset])
    cur.execute(query, params)
    logs = cur.fetchall()
    for log in logs:
        log['timestamp']  = str(log['timestamp'])
        log['created_at'] = str(log['created_at'])

    conn.close()
    return {
        'logs': logs,
        'total_pages':   max(1, (total + per_page - 1) // per_page),
        'current_page':  page,
        'total_records': total
    }

def get_all_logs():
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM firewall_logs ORDER BY timestamp DESC")
    logs = cur.fetchall()
    for log in logs:
        log['timestamp']  = str(log['timestamp'])
        log['created_at'] = str(log['created_at'])
    conn.close()
    return logs

def get_reports():
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT src_ip as ip, COUNT(*) as count,
               MAX(timestamp) as last_seen, port
        FROM firewall_logs WHERE action='DENY'
        GROUP BY src_ip, port
        ORDER BY count DESC LIMIT 5
    """)
    top_ips = cur.fetchall()
    for r in top_ips:
        r['last_seen'] = str(r['last_seen'])

    cur.execute("""
        SELECT port, COUNT(*) as count
        FROM firewall_logs WHERE action='DENY'
        GROUP BY port ORDER BY count DESC LIMIT 5
    """)
    ports = cur.fetchall()

    cur.execute("""
        SELECT protocol, COUNT(*) as count
        FROM firewall_logs GROUP BY protocol
    """)
    protocols = cur.fetchall()

    conn.close()
    return {
        'top_ips':   top_ips,
        'ports':     ports,
        'protocols': protocols
    }
# ── Auto Login System ─────────────────────────────────
def check_or_create_user(username, password, ip_address=''):
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)

    cur.execute("SELECT * FROM portal_users WHERE username=%s", (username,))
    user = cur.fetchone()

    if user:
        if user['password'] == password and user['status'] == 'active':
            # Update login info
            cur.execute("""
                UPDATE portal_users 
                SET last_login=NOW(), login_count=login_count+1
                WHERE username=%s
            """, (username,))

            # Login history
            cur.execute("""
                INSERT INTO login_history (username, role, ip_address, status)
                VALUES (%s, %s, %s, 'success')
            """, (username, user['role'], ip_address))

            # System logins
            cur.execute("SELECT dept FROM ad_users WHERE username=%s", (username,))
            ad_user = cur.fetchone()
            dept = ad_user['dept'] if ad_user else 'IT'
            system_name = f"PC-{dept}-{ip_address.split('.')[-1]}"
            cur.execute("""
                INSERT INTO system_logins
                (timestamp, system_name, ip_address, username,
                 department, event, duration, note)
                VALUES (NOW(), %s, %s, %s, %s, 'LOGIN', '—', 'Portal login')
            """, (system_name, ip_address, username, dept))

            # ── IP Threat Check ──────────────────────
            cur.execute("""
                SELECT * FROM threat_ips WHERE ip_address=%s
            """, (ip_address,))
            threat = cur.fetchone()

            if threat:
                cur.execute("""
                    INSERT INTO login_ip_threats
                    (username, ip_address, login_time,
                     threat_found, severity, events, status)
                    VALUES (%s, %s, NOW(), TRUE, %s, %s, 'threat')
                """, (username, ip_address,
                      threat['severity'], threat['events']))
            else:
                cur.execute("""
                    INSERT INTO login_ip_threats
                    (username, ip_address, login_time,
                     threat_found, severity, events, status)
                    VALUES (%s, %s, NOW(), FALSE, NULL, NULL, 'clean')
                """, (username, ip_address))

            conn.commit()
            conn.close()
            return {
                'success':      True,
                'username':     user['username'],
                'full_name':    user['full_name'],
                'role':         user['role'],
                'new_user':     False,
                'ip_threat':    threat is not None,
                'ip_severity':  threat['severity'] if threat else None
            }
        else:
            cur.execute("""
                INSERT INTO login_history (username, role, ip_address, status)
                VALUES (%s, %s, %s, 'failed')
            """, (username, user.get('role','Unknown'), ip_address))

            cur.execute("SELECT dept FROM ad_users WHERE username=%s", (username,))
            ad_user = cur.fetchone()
            dept = ad_user['dept'] if ad_user else 'Unknown'
            system_name = f"PC-{dept}-{ip_address.split('.')[-1]}"
            cur.execute("""
                INSERT INTO system_logins
                (timestamp, system_name, ip_address, username,
                 department, event, duration, note)
                VALUES (NOW(), %s, %s, %s, %s, 'FAILED', '—', 'Wrong password')
            """, (system_name, ip_address, username, dept))

            conn.commit()
            conn.close()
            return {'success': False}
    else:
        cur.execute("""
            INSERT INTO login_history (username, role, ip_address, status)
            VALUES (%s, 'Unknown', %s, 'failed')
        """, (username, ip_address))
        conn.commit()
        conn.close()
        return {'success': False}

# ── Get All Portal Users ──────────────────────────────
def get_portal_users():
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT id, username, full_name, email, role, status,
               last_login, login_count, created_at
        FROM portal_users
        ORDER BY last_login DESC
    """)
    users = cur.fetchall()
    for u in users:
        u['last_login'] = str(u['last_login']) if u['last_login'] else 'Never'
        u['created_at'] = str(u['created_at'])
    conn.close()
    return users

# ── Get Login History ─────────────────────────────────
def get_login_history(username='', status='', page=1, per_page=10):
    conn   = get_connection()
    cur    = conn.cursor(dictionary=True)
    offset = (page-1) * per_page

    query  = "SELECT * FROM login_history WHERE 1=1"
    params = []

    if username:
        query += " AND username LIKE %s"
        params.append(f"%{username}%")
    if status:
        query += " AND status=%s"
        params.append(status)

    count_query = query.replace("SELECT *", "SELECT COUNT(*) as total")
    cur.execute(count_query, params)
    total = cur.fetchone()['total']

    query += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
    params.extend([per_page, offset])
    cur.execute(query, params)
    logs = cur.fetchall()
    for log in logs:
        log['timestamp'] = str(log['timestamp'])

    conn.close()
    return {
        'logs':          logs,
        'total_pages':   max(1, (total+per_page-1)//per_page),
        'total_records': total
    }

# ── Update Portal User Role ───────────────────────────
def update_user_role(user_id, role, status):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        UPDATE portal_users SET role=%s, status=%s WHERE id=%s
    """, (role, status, user_id))
    conn.commit()
    conn.close()
    return True

# ── Delete Portal User ────────────────────────────────
def delete_portal_user(user_id):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("DELETE FROM portal_users WHERE id=%s", (user_id,))
    conn.commit()
    conn.close()
    return True

# ── AD Users MySQL se ─────────────────────────────────
def get_ad_users(search='', dept='', status=''):
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)
    query  = "SELECT * FROM ad_users WHERE 1=1"
    params = []
    if search:
        query += " AND (username LIKE %s OR fullname LIKE %s)"
        params.extend([f"%{search}%", f"%{search}%"])
    if dept:
        query += " AND dept=%s"
        params.append(dept)
    if status:
        query += " AND status=%s"
        params.append(status)
    cur.execute(query, params)
    users = cur.fetchall()
    for u in users:
        u['created_at'] = str(u['created_at'])
        u['updated_at'] = str(u['updated_at'])
    conn.close()
    return users

def get_ad_stats():
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT COUNT(*) as total FROM ad_users")
    total = cur.fetchone()['total']
    cur.execute("SELECT COUNT(*) as c FROM ad_users WHERE status='enabled'")
    enabled = cur.fetchone()['c']
    cur.execute("SELECT COUNT(*) as c FROM ad_users WHERE status='disabled'")
    disabled = cur.fetchone()['c']
    cur.execute("SELECT COUNT(*) as c FROM ad_users WHERE status='locked'")
    locked = cur.fetchone()['c']
    conn.close()
    return {
        'total':    total,
        'enabled':  enabled,
        'disabled': disabled,
        'locked':   locked
    }
def create_ad_user(data):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO ad_users (username, fullname, email, dept, role, status)
        VALUES (%s, %s, %s, %s, %s, 'enabled')
    """, (data['username'], data['fullname'], data['email'],
          data['dept'], data['role']))
    
    password = data.get('password', '')
    if password:
        ad_role = data['role']
        if 'IT' in ad_role or ad_role == 'Admin':
            portal_role = 'IT Admin'
        elif 'HR' in ad_role:
            portal_role = 'HR Admin'
        else:
            portal_role = 'Viewer'
        cur.execute("""
            INSERT IGNORE INTO portal_users
            (username, password, full_name, email, role, status)
            VALUES (%s, %s, %s, %s, %s, 'active')
        """, (data['username'], password, data['fullname'], 
              data['email'], portal_role))
    
    conn.commit()
    conn.close()
    
    # Update member counts automatically
    update_group_members_count()
    
    add_audit_log('admin', 'CREATE', data['username'],
                  f"User created in {data['dept']} OU", 'success')
    return True
def update_ad_user(user_id, data):
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT username FROM ad_users WHERE id=%s", (user_id,))
    old = cur.fetchone()
    cur.execute("""
        UPDATE ad_users
        SET fullname=%s, email=%s, dept=%s, role=%s
        WHERE id=%s
    """, (data['fullname'], data['email'],
          data['dept'], data['role'], user_id))
    conn.commit()
    conn.close()
    add_audit_log('admin', 'MODIFY', old['username'],
                  'User details updated', 'success')
    return True

def delete_ad_user(user_id):
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT username FROM ad_users WHERE id=%s", (user_id,))
    user = cur.fetchone()
    cur.execute("DELETE FROM ad_users WHERE id=%s", (user_id,))
    conn.commit()
    conn.close()
    add_audit_log('admin', 'DELETE', user['username'],
                  'User account deleted', 'success')
    return True

def toggle_ad_lock(user_id):
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT username, status FROM ad_users WHERE id=%s", (user_id,))
    user = cur.fetchone()
    new_status = 'enabled' if user['status'] == 'locked' else 'locked'
    cur.execute("UPDATE ad_users SET status=%s WHERE id=%s",
                (new_status, user_id))
    conn.commit()
    conn.close()
    action = 'LOCK' if new_status == 'locked' else 'MODIFY'
    add_audit_log('admin', action, user['username'],
                  f"Account {new_status}", 'success')
    return True

def add_audit_log(admin, action, target_user, details, status):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO ad_audit_logs
        (timestamp, admin, action, target_user, details, status)
        VALUES (NOW(), %s, %s, %s, %s, %s)
    """, (admin, action, target_user, details, status))
    conn.commit()
    conn.close()

def get_audit_logs(action='', date_filter=''):
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)
    query  = "SELECT * FROM ad_audit_logs WHERE 1=1"
    params = []
    if action:
        query += " AND action=%s"
        params.append(action)
    if date_filter:
        query += " AND DATE(timestamp)=%s"
        params.append(date_filter)
    query += " ORDER BY timestamp DESC"
    cur.execute(query, params)
    logs = cur.fetchall()
    for log in logs:
        log['timestamp']  = str(log['timestamp'])
        log['created_at'] = str(log['created_at'])
    conn.close()
    return logs

# ── AD Groups ─────────────────────────────────────────
def get_groups():
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM ad_groups ORDER BY name")
    groups = cur.fetchall()
    for g in groups:
        g['created_at'] = str(g['created_at'])
    conn.close()
    return groups

def create_group(data):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO ad_groups (name, members, description)
        VALUES (%s, %s, %s)
    """, (data['name'], data.get('members', 0), data.get('desc', '')))
    conn.commit()
    conn.close()
    return True

def delete_group(name):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("DELETE FROM ad_groups WHERE name=%s", (name,))
    conn.commit()
    conn.close()
    return True

# ── AD OUs ────────────────────────────────────────────
def get_ous():
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM ad_ous ORDER BY name")
    ous = cur.fetchall()
    for o in ous:
        o['created_at'] = str(o['created_at'])
    conn.close()
    return ous

def create_ou(data):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO ad_ous (name, users, path)
        VALUES (%s, %s, %s)
    """, (data['name'], data.get('users', 0),
          f"OU={data['name']},DC=corp,DC=local"))
    conn.commit()
    conn.close()
    return True

def delete_ou(name):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("DELETE FROM ad_ous WHERE name=%s", (name,))
    conn.commit()
    conn.close()
    return True
def reset_ad_user_password(user_id, new_password):
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)

    # Username dhundho
    cur.execute("SELECT username, fullname FROM ad_users WHERE id=%s", (user_id,))
    user = cur.fetchone()

    if not user:
        conn.close()
        return False

    username = user['username']

    # portal_users mein password update karo
    cur.execute("""
        UPDATE portal_users SET password=%s WHERE username=%s
    """, (new_password, username))

    # Agar portal_users mein nahi hai toh insert karo
    if cur.rowcount == 0:
        cur.execute("""
            INSERT IGNORE INTO portal_users
            (username, password, full_name, role, status)
            VALUES (%s, %s, %s, 'Viewer', 'active')
        """, (username, new_password, user['fullname']))

    conn.commit()
    conn.close()

    # Audit log mein entry karo
    add_audit_log('admin', 'RESET', username,
                  'Password reset via portal', 'success')
    return True

# ── Login IP Threat Check ─────────────────────────────
def check_login_ip_threat(username, ip_address):
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)

    # Threat database mein IP check karo
    cur.execute("""
        SELECT * FROM threat_ips WHERE ip_address=%s
    """, (ip_address,))
    threat = cur.fetchone()

    if threat:
        threat_found = True
        severity     = threat['severity']
        events       = threat['events']
        status       = 'threat'
    else:
        threat_found = False
        severity     = None
        events       = None
        status       = 'clean'

    # Login IP threat table mein save karo
    cur.execute("""
        INSERT INTO login_ip_threats
        (username, ip_address, login_time, threat_found, severity, events, status)
        VALUES (%s, %s, NOW(), %s, %s, %s, %s)
    """, (username, ip_address, threat_found, severity, events, status))

    conn.commit()
    conn.close()
    return {
        'threat_found': threat_found,
        'severity':     severity,
        'events':       events,
        'status':       status
    }

def get_login_ip_threats(page=1, per_page=10):
    conn   = get_connection()
    cur    = conn.cursor(dictionary=True)
    offset = (page-1) * per_page

    cur.execute("SELECT COUNT(*) as total FROM login_ip_threats")
    total = cur.fetchone()['total']

    cur.execute("""
        SELECT * FROM login_ip_threats
        ORDER BY login_time DESC
        LIMIT %s OFFSET %s
    """, (per_page, offset))
    logs = cur.fetchall()
    for log in logs:
        log['login_time'] = str(log['login_time'])

    conn.close()
    return {
        'logs':         logs,
        'total':        total,
        'total_pages':  max(1, (total+per_page-1)//per_page)
    }

def get_login_ip_threat_stats():
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)

    cur.execute("SELECT COUNT(*) as total FROM login_ip_threats")
    total = cur.fetchone()['total']

    cur.execute("SELECT COUNT(*) as c FROM login_ip_threats WHERE status='threat'")
    threats = cur.fetchone()['c']

    cur.execute("SELECT COUNT(*) as c FROM login_ip_threats WHERE status='clean'")
    clean = cur.fetchone()['c']

    cur.execute("""
        SELECT username, ip_address, severity, login_time
        FROM login_ip_threats
        WHERE status='threat'
        ORDER BY login_time DESC
        LIMIT 5
    """)
    recent_threats = cur.fetchall()
    for r in recent_threats:
        r['login_time'] = str(r['login_time'])

    conn.close()
    return {
        'total':          total,
        'threats':        threats,
        'clean':          clean,
        'recent_threats': recent_threats
    }
def update_group_members_count():
    """Update member counts based on actual ad_users data"""
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)
    
    # Get count per department
    cur.execute("""
        SELECT dept, COUNT(*) as cnt 
        FROM ad_users 
        WHERE status='enabled' 
        GROUP BY dept
    """)
    dept_counts = {row['dept']: row['cnt'] for row in cur.fetchall()}
    
    # Map dept to group
    dept_group_map = {
        'IT':      'IT-Admins',
        'HR':      'HR-Staff',
        'Finance': 'Finance-Team',
        'Sales':   'Sales-Team'
    }
    
    for dept, group_name in dept_group_map.items():
        count = dept_counts.get(dept, 0)
        cur.execute("""
            UPDATE ad_groups SET members=%s WHERE name=%s
        """, (count, group_name))
        cur.execute("""
            UPDATE ad_ous SET users=%s 
            WHERE name LIKE %s
        """, (count, f"%{dept}%"))
    
    conn.commit()
    conn.close()