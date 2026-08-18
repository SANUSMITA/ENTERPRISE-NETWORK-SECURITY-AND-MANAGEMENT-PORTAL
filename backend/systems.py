import mysql.connector
import config

def get_connection():
    return mysql.connector.connect(
        host     = config.DB_HOST,
        user     = config.DB_USER,
        password = config.DB_PASSWORD,
        database = config.DB_NAME
    )

def get_systems():
    conn = get_connection()
    cur  = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT
            system_name, ip_address, department,
            MAX(CASE WHEN event='LOGIN'  THEN username  END) as last_user,
            MAX(CASE WHEN event='LOGIN'  THEN timestamp END) as last_login,
            MAX(CASE WHEN event='LOGOUT' THEN timestamp END) as last_logout,
            SUM(CASE WHEN event='LOGIN'  THEN 1 ELSE 0 END)  as sessions
        FROM system_logins
        GROUP BY system_name, ip_address, department
        ORDER BY last_login DESC
    """)
    systems = cur.fetchall()
    for s in systems:
        s['last_login']  = str(s['last_login'])  if s['last_login']  else '—'
        s['last_logout'] = str(s['last_logout']) if s['last_logout'] else '—'
        sessions = s['sessions'] or 0
        if sessions == 0:
            s['status'] = 'inactive'
        elif str(s['last_logout']) == '—':
            s['status'] = 'idle'
        else:
            s['status'] = 'active'
    conn.close()
    return systems

def get_system_logs(system='', user='', event='', date_filter='', page=1, per_page=10):
    conn   = get_connection()
    cur    = conn.cursor(dictionary=True)
    offset = (page - 1) * per_page
    query  = "SELECT * FROM system_logins WHERE 1=1"
    params = []

    if system:
        query += " AND system_name LIKE %s"
        params.append(f"%{system}%")
    if user:
        query += " AND username LIKE %s"
        params.append(f"%{user}%")
    if event:
        query += " AND event=%s"
        params.append(event)
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
        'logs':          logs,
        'total_pages':   max(1, (total + per_page - 1) // per_page),
        'current_page':  page,
        'total_records': total
    }