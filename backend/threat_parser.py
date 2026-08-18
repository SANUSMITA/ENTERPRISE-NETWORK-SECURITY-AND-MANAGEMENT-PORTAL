import re
import fitz

def get_severity_by_sno(sno):
    if sno <= 63:
        return 'Very High'
    elif sno <= 163:
        return 'High'
    elif sno <= 441:
        return 'Medium'
    else:
        return 'Low'

def parse_threat_pdf(pdf_path):
    ip_data   = []
    hash_data = []

    ip_pattern   = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'

    doc = fitz.open(pdf_path)

    for page_num in range(len(doc)):
        page = doc[page_num]
        text = page.get_text()
        if not text.strip():
            continue

        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # IP dhundho
            ip_matches = re.findall(ip_pattern, line)
            for ip in ip_matches:
                # Skip private/local IPs
                if ip.startswith(('192.168.','10.','172.','127.')):
                    continue

                # S.No dhundho line mein
                sno_match = re.match(r'^(\d+)', line)
                sno = int(sno_match.group(1)) if sno_match else len(ip_data)+1

                # Severity by S.No
                sev = get_severity_by_sno(sno)

                # Events nikalo
                rest = re.sub(ip_pattern, '', line)
                rest = re.sub(
                    r'very high|high|medium|low|\b\d+\b',
                    '', rest, flags=re.IGNORECASE
                ).strip()
                rest = re.sub(r'\s+', ' ', rest).strip()

                ip_data.append({
                    's_no':       sno,
                    'ip_address': ip,
                    'events':     rest[:200],
                    'severity':   sev
                })

            # Hash dhundho
            hash_matches = re.findall(hash_pattern, line)
            for h in hash_matches:
                if len(h) >= 32:
                    sev = 'High'
                    ll  = line.lower()
                    if 'very high' in ll:
                        sev = 'Very High'
                    elif 'medium' in ll:
                        sev = 'Medium'
                    elif 'low' in ll:
                        sev = 'Low'

                    hash_data.append({
                        's_no':        len(hash_data) + 1,
                        'hash_value':  h,
                        'events':      line[:100],
                        'severity':    sev,
                        'av_class':    '',
                        'av_labeling': ''
                    })

    doc.close()

    # Duplicates remove
    seen = set()
    unique_ips = []
    for ip in ip_data:
        if ip['ip_address'] not in seen:
            seen.add(ip['ip_address'])
            unique_ips.append(ip)

    print(f"Parsed: {len(unique_ips)} IPs, {len(hash_data)} hashes")
    return unique_ips, hash_data


def save_to_db(ip_data, hash_data, filename, uploaded_by, db):
    conn = db.get_connection()
    cur  = conn.cursor()

    cur.execute("DELETE FROM threat_ips WHERE source='CERT-In'")
    cur.execute("DELETE FROM threat_hashes WHERE source='CERT-In'")

    ip_count = 0
    for ip in ip_data:
        try:
            cur.execute("""
                INSERT INTO threat_ips
                (s_no, ip_address, events, severity, source)
                VALUES (%s, %s, %s, %s, 'CERT-In')
            """, (ip['s_no'], ip['ip_address'],
                  ip['events'], ip['severity']))
            ip_count += 1
        except Exception as e:
            print(f"IP error: {e}")
            continue

    hash_count = 0
    for h in hash_data:
        try:
            cur.execute("""
                INSERT INTO threat_hashes
                (s_no, hash_value, events, severity,
                 av_class, av_labeling, source)
                VALUES (%s, %s, %s, %s, %s, %s, 'CERT-In')
            """, (h['s_no'], h['hash_value'], h['events'],
                  h['severity'], h['av_class'], h['av_labeling']))
            hash_count += 1
        except Exception as e:
            print(f"Hash error: {e}")
            continue

    cur.execute("""
        INSERT INTO threat_uploads
        (filename, ip_count, hash_count, uploaded_by)
        VALUES (%s, %s, %s, %s)
    """, (filename, ip_count, hash_count, uploaded_by))

    conn.commit()
    conn.close()
    return ip_count, hash_count