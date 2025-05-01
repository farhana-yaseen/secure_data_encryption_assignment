import streamlit as st
import json
import os
import base64
import time
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# --- Config ---
USER_FILE = "users.json"
DATA_FILE = "data_store.json"
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 60  # in seconds

backend = default_backend()


# --- Utility Functions ---
def load_json(path):
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump({}, f)
    with open(path, "r") as f:
        return json.load(f)

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


# --- Key Derivation ---
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=backend
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


# --- User Management ---
def create_user(username: str, password: str):
    users = load_json(USER_FILE)
    if username in users:
        return False, "Username already exists."
    salt = os.urandom(16)
    key = derive_key(password, salt)
    users[username] = {
        "salt": base64.b64encode(salt).decode(),
        "key": key.decode()
    }
    save_json(USER_FILE, users)
    return True, "User created."

def authenticate_user(username: str, password: str):
    users = load_json(USER_FILE)
    if username not in users:
        return False
    salt = base64.b64decode(users[username]["salt"])
    stored_key = users[username]["key"]
    try:
        derived = derive_key(password, salt)
        return derived.decode() == stored_key
    except Exception:
        return False


# --- Encryption / Decryption ---
def encrypt_data(username: str, passkey: str, data: str):
    key = derive_key(passkey, username.encode())
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(username: str, passkey: str, token: str):
    key = derive_key(passkey, username.encode())
    f = Fernet(key)
    return f.decrypt(base64.b64decode(token)).decode()


# --- Session State ---
if "user" not in st.session_state:
    st.session_state.user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = {}
if "lockout" not in st.session_state:
    st.session_state.lockout = {}


# --- Lockout Logic ---
def is_locked_out(username):
    until = st.session_state.lockout.get(username)
    return until and time.time() < until

def register_failed(username):
    st.session_state.failed_attempts[username] = st.session_state.failed_attempts.get(username, 0) + 1
    if st.session_state.failed_attempts[username] >= MAX_ATTEMPTS:
        st.session_state.lockout[username] = time.time() + LOCKOUT_TIME
        st.warning(f"User locked out for {LOCKOUT_TIME} seconds.")
        st.session_state.failed_attempts[username] = 0

def reset_attempts(username):
    st.session_state.failed_attempts[username] = 0
    if username in st.session_state.lockout:
        del st.session_state.lockout[username]


# --- App Layout ---
st.title("🔐 Secure Data Vault")

if st.session_state.user:
    st.sidebar.success(f"Logged in as: {st.session_state.user}")
    if st.sidebar.button("Logout"):
        st.session_state.user = None
        st.rerun()
else:
    option = st.radio("Select action:", ["Login", "Register"])

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if option == "Register":
        if st.button("Create Account"):
            success, msg = create_user(username, password)
            st.success(msg) if success else st.error(msg)

    elif option == "Login":
        if is_locked_out(username):
            st.error("Account locked. Try again later.")
        elif st.button("Login"):
            if authenticate_user(username, password):
                reset_attempts(username)
                st.session_state.user = username
                st.success("Login successful!")
                st.rerun()
            else:
                register_failed(username)
                st.error("Invalid credentials.")


# --- Main Functionality ---
if st.session_state.user:
    tab1, tab2 = st.tabs(["Store Data", "Retrieve Data"])

    with tab1:
        st.subheader("Store Encrypted Data")
        passkey = st.text_input("Passkey", type="password", key="store_key")
        message = st.text_area("Data to store")
        if st.button("Encrypt & Save"):
            if passkey and message:
                encrypted = encrypt_data(st.session_state.user, passkey, message)
                data_store = load_json(DATA_FILE)
                data_store[st.session_state.user] = base64.b64encode(encrypted).decode()
                save_json(DATA_FILE, data_store)
                st.success("Data encrypted and saved.")
            else:
                st.warning("Provide both passkey and message.")

    with tab2:
        st.subheader("Retrieve Encrypted Data")
        passkey = st.text_input("Passkey", type="password", key="retrieve_key")
        if st.button("Decrypt & Load"):
            data_store = load_json(DATA_FILE)
            encrypted = data_store.get(st.session_state.user)
            if not encrypted:
                st.warning("No data found.")
            else:
                try:
                    decrypted = decrypt_data(st.session_state.user, passkey, encrypted)
                    st.success("Decryption successful.")
                    st.code(decrypted)
                except InvalidToken:
                    st.error("Invalid passkey.")
