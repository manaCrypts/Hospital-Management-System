"""
CS-3002 Information Security — Assignment #4
GDPR-inspired Mini Hospital Management System
Run: streamlit run app.py
Demo accounts (change passwords before real deployment):
  admin / admin123
  doctor / doc123
  receptionist / rec123

Security note: This is an educational demonstration, not a production medical system.
Keep the generated .key file secret and outside version control. Use HTTPS, managed
secrets, backups, and a security review before handling real patient information.
"""
import streamlit as st
import sqlite3, hashlib, hmac, os, csv, io, time
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
    FERNET_AVAILABLE = True
except ImportError:
    FERNET_AVAILABLE = False

DB_PATH = Path(__file__).with_name("hospital.db")
KEY_PATH = Path(__file__).with_name("fernet.key")
START_TIME = time.time()
st.set_page_config(page_title="CareShield | Hospital Dashboard", page_icon="🏥", layout="wide")

def now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def connect():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    return con

def password_hash(password, salt=None):
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260000)
    return salt.hex() + "$" + digest.hex()

def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 260000)
        return hmac.compare_digest(candidate.hex(), digest_hex)
    except Exception:
        return False

def get_cipher():
    if not FERNET_AVAILABLE:
        return None
    if not KEY_PATH.exists():
        KEY_PATH.write_bytes(Fernet.generate_key())
        try: os.chmod(KEY_PATH, 0o600)
        except OSError: pass
    return Fernet(KEY_PATH.read_bytes())

def init_db():
    with connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          user_id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','doctor','receptionist'))
        );
        CREATE TABLE IF NOT EXISTS patients(
          patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL, contact TEXT NOT NULL, diagnosis TEXT NOT NULL,
          anonymized_name TEXT, anonymized_contact TEXT, anonymized_diagnosis TEXT,
          encrypted_name BLOB, encrypted_contact BLOB, encrypted_diagnosis BLOB,
          consent INTEGER NOT NULL DEFAULT 0 CHECK(consent IN (0,1)),
          date_added TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS logs(
          log_id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER, username TEXT NOT NULL, role TEXT NOT NULL,
          action TEXT NOT NULL, timestamp TEXT NOT NULL, details TEXT,
          FOREIGN KEY(user_id) REFERENCES users(user_id)
        );
        """)
        defaults = [
            ("admin", "admin123", "admin"),
            ("doctor", "doc123", "doctor"),
            ("receptionist", "rec123", "receptionist")
        ]
        for username, password, role in defaults:
            exists = con.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
            if not exists:
                con.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                            (username, password_hash(password), role))

def log_action(action, details=""):
    u = st.session_state.get("user")
    if not u: return
    with connect() as con:
        con.execute("INSERT INTO logs(user_id,username,role,action,timestamp,details) VALUES(?,?,?,?,?,?)",
                    (u["user_id"], u["username"], u["role"], action, now(), details[:500]))

def mask_contact(value):
    digits = "".join(c for c in str(value) if c.isdigit())
    return "XXX-XXX-" + digits[-4:] if len(digits) >= 4 else "XXX-XXX-XXXX"

def anonymize_patient(row, cipher):
    pid = row["patient_id"]
    anon_name = f"ANON_{1000 + pid}"
    anon_contact = mask_contact(row["contact"])
    anon_diagnosis = "REDACTED"  # diagnosis is sensitive; do not expose it by default
    encrypted = [None, None, None]
    if cipher:
        encrypted = [cipher.encrypt(row[k].encode()) for k in ("name","contact","diagnosis")]
    return anon_name, anon_contact, anon_diagnosis, encrypted

def login():
    st.title("🏥 CareShield Hospital Management")
    st.caption("Privacy-first patient records • CS-3002 Information Security")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in", use_container_width=True)
    if submitted:
        try:
            with connect() as con:
                user = con.execute("SELECT * FROM users WHERE username=?", (username.strip(),)).fetchone()
            if user and verify_password(password, user["password_hash"]):
                st.session_state.user = dict(user)
                log_action("LOGIN", "Successful authentication")
                st.rerun()
            else:
                st.error("Login failed. Check your username and password.")
                st.session_state.user = None
                # failed attempts are not attributed to an authenticated user
        except sqlite3.Error:
            st.error("Database unavailable. Please retry in a moment.")
    with st.expander("Demo login accounts"):
        st.code("admin / admin123\ndoctor / doc123\nreceptionist / rec123")
        st.warning("These are demonstration credentials. Change them before deployment.")

def add_patient():
    st.subheader("Register / update patient")
    st.caption("Receptionists can enter records but cannot browse or read sensitive patient fields.")
    mode = st.radio("Action", ["Add new record", "Edit existing record"], horizontal=True)
    with st.form("patient_form", clear_on_submit=True):
        patient_id = st.number_input("Patient ID (required for edit; ask admin for the ID)", min_value=1, step=1) if mode == "Edit existing record" else None
        name = st.text_input("Patient name")
        contact = st.text_input("Contact number")
        diagnosis = st.text_area("Diagnosis")
        consent = st.checkbox("Patient consent recorded for the stated processing purpose")
        submitted = st.form_submit_button("Save changes" if mode == "Edit existing record" else "Save patient")
    if submitted:
        if not name.strip() or not contact.strip() or not diagnosis.strip():
            st.error("All fields are required.")
            return
        if len(name) > 100 or len(contact) > 30 or len(diagnosis) > 500:
            st.error("Input exceeds the allowed length.")
            return
        try:
            with connect() as con:
                if mode == "Add new record":
                    con.execute("""INSERT INTO patients(name,contact,diagnosis,consent,date_added,updated_at)
                                   VALUES(?,?,?,?,?,?)""",
                                (name.strip(), contact.strip(), diagnosis.strip(), int(consent), now(), now()))
                    pid = con.execute("SELECT last_insert_rowid()").fetchone()[0]
                    action = "ADD_RECORD"
                else:
                    cur = con.execute("""UPDATE patients SET name=?,contact=?,diagnosis=?,consent=?,updated_at=?
                                         WHERE patient_id=?""",
                                      (name.strip(), contact.strip(), diagnosis.strip(), int(consent), now(), int(patient_id)))
                    if cur.rowcount == 0:
                        st.error("No record exists with that patient ID.")
                        return
                    pid = int(patient_id)
                    action = "UPDATE_RECORD"
            log_action(action, f"Patient record ID {pid}; consent={bool(consent)}")
            st.success(f"Patient record {pid} saved.")
        except sqlite3.Error:
            st.error("Could not save the record. No changes were confirmed.")

def admin_view():
    st.subheader("Administrator: patient records")
    with connect() as con:
        rows = con.execute("""SELECT patient_id,name,contact,diagnosis,anonymized_name,
                            anonymized_contact,anonymized_diagnosis,consent,date_added,updated_at
                            FROM patients ORDER BY patient_id DESC""").fetchall()
    if not rows:
        st.info("No patient records yet.")
    else:
        st.dataframe([dict(r) for r in rows], use_container_width=True, hide_index=True)
    if st.button("Anonymize all records", type="primary"):
        cipher = get_cipher()
        try:
            with connect() as con:
                patients = con.execute("SELECT * FROM patients").fetchall()
                for p in patients:
                    an, ac, ad, enc = anonymize_patient(p, cipher)
                    con.execute("""UPDATE patients SET anonymized_name=?, anonymized_contact=?,
                                anonymized_diagnosis=?, encrypted_name=?, encrypted_contact=?,
                                encrypted_diagnosis=?, updated_at=? WHERE patient_id=?""",
                                (an,ac,ad,*enc,now(),p["patient_id"]))
            log_action("ANONYMIZE", f"Anonymized {len(patients)} patient records")
            st.success(f"Anonymized {len(patients)} records.")
            st.rerun()
        except (sqlite3.Error, OSError) as e:
            st.error(f"Anonymization failed: {e}")
    st.caption("Fernet encryption is enabled when the cryptography package is installed.")

def doctor_view():
    st.subheader("Doctor: anonymized patient data")
    with connect() as con:
        rows = con.execute("""SELECT patient_id,anonymized_name,anonymized_contact,
                            anonymized_diagnosis,date_added FROM patients ORDER BY patient_id DESC""").fetchall()
    if not rows:
        st.info("No anonymized records available. Ask an administrator to run anonymization.")
    else:
        st.dataframe([dict(r) for r in rows], use_container_width=True, hide_index=True)
    log_action("VIEW_ANONYMIZED", f"Viewed {len(rows)} anonymized rows")

def receptionist_view():
    st.subheader("Receptionist workspace")
    add_patient()
    st.divider()
    st.markdown("**Record status**")
    with connect() as con:
        total = con.execute("SELECT COUNT(*) FROM patients").fetchone()[0]
    st.metric("Total registered records", total)
    st.info("Sensitive names, contacts and diagnoses are not displayed in this role.")

def audit_view():
    st.subheader("Integrity Audit Log")
    with connect() as con:
        logs = con.execute("SELECT log_id,username,role,action,timestamp,details FROM logs ORDER BY log_id DESC LIMIT 500").fetchall()
    st.dataframe([dict(r) for r in logs], use_container_width=True, hide_index=True)
    log_action("VIEW_AUDIT_LOG", f"Viewed {len(logs)} audit events")

def export_data():
    st.subheader("Backup & export")
    role = st.session_state.user["role"]
    if role != "admin":
        st.info("Only administrators can export raw backup data.")
        return
    with connect() as con:
        rows = con.execute("SELECT * FROM patients ORDER BY patient_id").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    if rows:
        writer.writerow(rows[0].keys())
        for row in rows: writer.writerow([row[k] for k in row.keys()])
    else:
        writer.writerow(["patient_id","name","contact","diagnosis"])
    st.download_button("Download patient backup (CSV)", output.getvalue(),
                       file_name="hospital_backup.csv", mime="text/csv")
    log_action("EXPORT_CSV", f"Prepared backup containing {len(rows)} rows")

def main():
    init_db()
    if not st.session_state.get("user"):
        login()
        return
    user = st.session_state.user
    st.sidebar.title("CareShield")
    st.sidebar.write(f"**{user['username']}**")
    st.sidebar.caption(f"Role: {user['role'].title()}")
    if st.sidebar.button("Log out"):
        log_action("LOGOUT", "User signed out")
        st.session_state.user = None
        st.rerun()
    st.title("Hospital Management Dashboard")
    st.caption("Privacy, trust and the CIA Triad")
    c1,c2,c3 = st.columns(3)
    with connect() as con:
        total = con.execute("SELECT COUNT(*) FROM patients").fetchone()[0]
    c1.metric("Patient records", total)
    c2.metric("Access role", user["role"].title())
    c3.metric("Database", "Connected")
    st.divider()
    if user["role"] == "admin":
        tabs = st.tabs(["Patient data","Audit log","Backup"])
        with tabs[0]: admin_view()
        with tabs[1]: audit_view()
        with tabs[2]: export_data()
    elif user["role"] == "doctor":
        doctor_view()
    elif user["role"] == "receptionist":
        receptionist_view()
    st.divider()
    uptime = int(time.time() - START_TIME)
    st.caption(f"System uptime (this app session): {uptime//3600:02d}h {(uptime%3600)//60:02d}m • Last sync: {now()} • SQLite WAL enabled")

if __name__ == "__main__":
    try:
        main()
    except sqlite3.Error:
        st.error("A database error occurred. Your session is still active; please retry.")
