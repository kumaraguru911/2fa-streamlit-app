import streamlit as st  # type: ignore
import bcrypt  # type: ignore
import pyotp  # type: ignore
import qrcode  # type: ignore
from io import BytesIO
import database as db

# Initialize DB
db.init_db()

# Streamlit page config
st.set_page_config(page_title="Secure 2FA App", layout="centered")

st.markdown(
    """
    <h1 style='text-align: center; color: #4CAF50;'>🔐 Secure 2FA App</h1>
    <p style='text-align: center;'>A modern web app demo for Two-Factor Authentication (TOTP)</p>
    <hr style='border: 1px solid #ddd;'>
    """,
    unsafe_allow_html=True
)

# Initialize session state variables
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = ""

# Dark mode toggle
dark_mode = st.sidebar.checkbox("🌙 Dark Mode")

# Apply dark or light mode styles dynamically
if dark_mode:
    st.markdown("""
    <style>
        body {
            background-color: #181818;
            color: #f0f0f0;
        }
        .stApp {
            background-color: #181818;
            color: #f0f0f0;
        }
        .css-1d391kg, .css-1vq4p4l, .css-ffhzg2 {  /* Main containers & widgets */
            background-color: #252525;
            color: #f0f0f0;
        }
        div.stButton > button:first-child {
            background-color: #e91e63;  /* A bright pink button in dark mode */
            color: white;
        }
        div.stButton > button:first-child:hover {
            background-color: #d81b60;
        }
        hr {
            border-color: #555;
        }
    </style>
    """, unsafe_allow_html=True)


tabs = st.tabs(["📝 Register", "🔑 Login"])

# -------- Register Tab --------
with tabs[0]:
    st.subheader("Create a new account")
    with st.form("register_form"):
        reg_username = st.text_input("👤 Username")
        reg_password = st.text_input("🔒 Password", type="password")
        register_btn = st.form_submit_button("Register", type="primary")

    if register_btn:
        if reg_username == "" or reg_password == "":
            st.error("Username and password cannot be empty!")
        elif db.get_user(reg_username):
            st.error("Username already exists!")
        else:
            hashed_pw = bcrypt.hashpw(reg_password.encode(), bcrypt.gensalt()).decode()
            totp_secret = pyotp.random_base32()
            db.add_user(reg_username, hashed_pw, totp_secret)
            st.success("✅ User registered successfully!")

            # Generate QR code
            totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(
                name=reg_username, issuer_name="Secure2FAApp"
            )
            qr_img = qrcode.make(totp_uri)
            buf = BytesIO()
            qr_img.save(buf, format="PNG")
            st.image(buf.getvalue(), caption="📱 Scan this QR code with your Authenticator app")

# -------- Login Tab --------
with tabs[1]:
    st.subheader("Sign in to your account")
    with st.form("login_form"):
        login_username = st.text_input("👤 Username", key="login_user")
        login_password = st.text_input("🔒 Password", type="password", key="login_pass")
        login_btn = st.form_submit_button("Login", type="primary")

    if login_btn:
        user = db.get_user(login_username)
        if not user:
            st.error("❌ User not found!")
        elif user[4]:  # is_locked
            st.error("🚫 Account is locked. Contact admin.")
        elif not bcrypt.checkpw(login_password.encode(), user[1].encode()):
            st.error("❌ Incorrect password.")
            new_attempts = user[3] + 1
            db.update_failed_attempts(login_username, new_attempts)
            db.add_audit_log(login_username, "Failed password")
            if new_attempts >= 3:
                db.lock_user(login_username)
                st.error("🚫 Account locked after 3 failed attempts!")
        else:
            st.session_state.username = login_username
            st.session_state.logged_in = False  # wait for 2FA
            st.success("✅ Password correct! Please enter your 2FA code below.")
            db.update_failed_attempts(login_username, 0)
            db.add_audit_log(login_username, "Successful password")

    if st.session_state.username and not st.session_state.logged_in:
        st.markdown("<hr>", unsafe_allow_html=True)
        st.subheader("🔒 Enter 2FA Code")
        totp_input = st.text_input("Enter the 6-digit code from your Authenticator app", key="totp_input")
        if st.button("Verify 2FA"):
            user = db.get_user(st.session_state.username)
            totp = pyotp.TOTP(user[2])  # totp_secret
            if totp.verify(totp_input):
                st.session_state.logged_in = True
                st.success(f"🎉 Welcome, {st.session_state.username}! You are fully logged in.")
                db.add_audit_log(st.session_state.username, "2FA success")
            else:
                st.error("❌ Invalid 2FA code!")
                db.add_audit_log(st.session_state.username, "2FA failure")

# -------- Admin panel --------
st.sidebar.title("🛠️ Admin Panel")

# Admin authentication
admin_code = st.sidebar.text_input("🔑 Enter admin code", type="password")
if admin_code == "admin123":  # change this to your secret code
    st.sidebar.success("Admin access granted!")

    if st.sidebar.checkbox("Show Registered Users", key="show_users"):
        users = db.get_all_users()
        if users:
            st.sidebar.write("**Users:**")
            st.sidebar.table(
                [{"Username": u[0], "Locked": bool(u[1]), "Failed Attempts": u[2]} for u in users]
            )
        else:
            st.sidebar.info("No users registered yet.")

    if st.sidebar.checkbox("Show Audit Logs", key="show_logs"):
        logs = db.get_audit_logs()
        if logs:
            st.sidebar.write("**Audit Log:**")
            st.sidebar.table(
                [{"Username": l[0], "Action": l[1], "Timestamp": l[2]} for l in logs]
            )
        else:
            st.sidebar.info("No audit logs yet.")

    st.sidebar.title("🔧 Admin Actions")

    if st.sidebar.checkbox("Delete a User", key="delete_user"):
        del_user = st.sidebar.text_input("Username to delete", key="del_username")
        if st.sidebar.button("Delete User", key="del_button"):
            db.delete_user(del_user)
            st.sidebar.success(f"Deleted user: {del_user}")

    if st.sidebar.checkbox("Unlock User Account", key="unlock_user"):
        unlock_user = st.sidebar.text_input("Username to unlock", key="unlock_username")
        if st.sidebar.button("Unlock User", key="unlock_button"):
            db.unlock_user(unlock_user)
            db.reset_failed_attempts(unlock_user)
            st.sidebar.success(f"Unlocked and reset attempts for: {unlock_user}")

    if st.sidebar.checkbox("Rotate User TOTP Secret", key="rotate_totp"):
        user_for_totp = st.sidebar.text_input("Username for new TOTP secret", key="rotate_username")
        if st.sidebar.button("Rotate Secret", key="rotate_button"):
            new_secret = pyotp.random_base32()
            db.update_totp_secret(user_for_totp, new_secret)
            st.sidebar.success(f"Updated TOTP secret for {user_for_totp}")
else:
    st.sidebar.warning("Enter the correct admin code to access admin features.")

st.markdown("""
<style>
    div.stButton > button:first-child {
        background-color: #4CAF50;
        color: white;
        font-size: 16px;
        padding: 0.5em 1.2em;
        border-radius: 8px;
        border: none;
    }
    div.stButton > button:first-child:hover {
        background-color: #45a049;
    }
</style>
""", unsafe_allow_html=True)

st.sidebar.markdown("""
<style>
    .sidebar .block-container {
        background-color: #f9f9f9;
        padding: 20px 10px;
        border-radius: 10px;
    }
    .sidebar h1, .sidebar h2, .sidebar h3 {
        color: #4CAF50;
    }
</style>
""", unsafe_allow_html=True)
