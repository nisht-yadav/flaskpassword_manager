# app.py
import os
import sqlite3
import hashlib
import base64
import hmac
import random
import string
import secrets
import gc
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from typing import Tuple, Optional, Dict, List, Any

# Constants
ITERATIONS = 600_000
SALT_SIZE = 16
AES_KEY_SIZE = 32  # Using AES-256
DB_NAME = 'password_vault.db'

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key for Flask

# Initialize database
def initialize_database():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        # Create users table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            master_hash BLOB NOT NULL,
            salt BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
        """)
        # Create passwords table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            password_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            site_url TEXT NOT NULL,
            site_username TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            entry_salt BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
        """)
        # Create password history table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            history_id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_id INTEGER NOT NULL,
            encrypted_password TEXT NOT NULL,
            entry_salt BLOB NOT NULL,
            changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (password_id) REFERENCES passwords(password_id) ON DELETE CASCADE
        )
        """)
        # Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_passwords_user_id ON passwords(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_passwords_site_url ON passwords(site_url)")
        conn.commit()

initialize_database()  # Initialize database at startup

# Password generation and validation
def generate_password(length: int) -> str:
    all_characters = string.ascii_letters + string.digits + string.punctuation
    password = [
        random.choice(string.ascii_lowercase),
        random.choice(string.ascii_uppercase),
        random.choice(string.digits),
        random.choice(string.punctuation)
    ]
    password += random.choices(all_characters, k=length - 4)
    random.shuffle(password)
    return ''.join(password)

def is_strong_password(password: str) -> bool:
    if len(password) < 12:
        return False
    has_upper = False
    has_lower = False
    has_digit = False
    has_special = False
    for char in password:
        if char.isupper(): has_upper = True
        elif char.islower(): has_lower = True
        elif char.isdigit(): has_digit = True
        elif char in string.punctuation: has_special = True
    return has_upper and has_lower and has_digit and has_special

# Authentication functions
def hash_password(password: str) -> Tuple[bytes, bytes]:
    salt = os.urandom(SALT_SIZE)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS)
    return dk, salt

def verify_master_password(entered_password: str, user_name: str) -> Tuple[bytes, int]:
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('SELECT salt, master_hash, user_id FROM users WHERE username = ?', (user_name,))
        row = c.fetchone()
    if row is None:
        raise ValueError("Invalid username or password.")
    salt, stored_hash, user_id = row
    entered_hash = hashlib.pbkdf2_hmac('sha256', entered_password.encode(), salt, ITERATIONS)
    if hmac.compare_digest(entered_hash, stored_hash):
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?', (user_id,))
            conn.commit()
        return salt, user_id
    else:
        raise ValueError("Incorrect master password.")

# Encryption and decryption functions
def derive_aes_key(master_password: str, salt: bytes, key_size: int = AES_KEY_SIZE) -> str:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(master_password.encode())
    return base64.urlsafe_b64encode(key).decode('utf-8')

def encrypt(plain_text: str, key: str) -> Tuple[str, bytes]:
    key_bytes = base64.urlsafe_b64decode(key)
    data = plain_text.encode('utf-8')
    iv = get_random_bytes(16)
    per_entry_salt = secrets.token_bytes(SALT_SIZE)
    entry_kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=per_entry_salt,
        iterations=1000,
        backend=default_backend()
    )
    entry_key = entry_kdf.derive(key_bytes)
    cipher = AES.new(entry_key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    cipher_text = cipher.encrypt(padded_data)
    final_data = iv + cipher_text
    return base64.b64encode(final_data).decode('utf-8'), per_entry_salt

def decrypt(enc_text: str, key: str, per_entry_salt: bytes) -> str:
    key_bytes = base64.urlsafe_b64decode(key)
    data = base64.b64decode(enc_text)
    iv = data[:16]
    cipher_text = data[16:]
    entry_kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=per_entry_salt,
        iterations=1000,
        backend=default_backend()
    )
    entry_key = entry_kdf.derive(key_bytes)
    cipher = AES.new(entry_key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(cipher_text)
    unpadded_data = unpad(decrypted_data, AES.block_size)
    return unpadded_data.decode('utf-8')

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].replace(" ", "")
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validate input
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("SELECT user_id FROM users WHERE username=?", (username,))
            if c.fetchone() is not None:
                flash('Username already exists', 'danger')
                return redirect(url_for('login'))  # Redirect to login page
        
        if not is_strong_password(password):
            flash('Password must be at least 12 characters and include uppercase, lowercase, digits, and special characters', 'danger')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        # Register user
        hashed, salt = hash_password(password)
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (username, master_hash, salt, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                (username, hashed, salt)
            )
            conn.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            salt, user_id = verify_master_password(password, username)
            session['user_id'] = user_id
            session['username'] = username
            session['master_password'] = password  # Store temporarily for encryption/decryption
            session['salt'] = salt
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        except ValueError:
            flash('Invalid username or password', 'danger')  # General error message
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM passwords WHERE user_id = ?", (session['user_id'],))
        password_count = c.fetchone()[0]
    
    return render_template('dashboard.html', username=session['username'], password_count=password_count)

@app.route('/passwords')
@login_required
def view_passwords():
    if 'master_password' not in session:
        flash('Session expired, please login again', 'danger')
        return redirect(url_for('login'))
    
    aes_key = derive_aes_key(session['master_password'], session['salt'])
    
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute(
            "SELECT password_id, site_url, site_username, encrypted_password, entry_salt, notes, created_at, last_updated "
            "FROM passwords WHERE user_id = ? ORDER BY site_url",
            (session['user_id'],)
        )
        data = c.fetchall()
    
    passwords = []
    for entry in data:
        password_id, site_url, site_username, encrypted_password, entry_salt, notes, created_at, last_updated = entry
        try:
            decrypted_password = decrypt(encrypted_password, aes_key, entry_salt)
            passwords.append({
                'id': password_id,
                'site_url': site_url,
                'username': site_username,
                'password': decrypted_password,
                'notes': notes,
                'created_at': created_at,
                'last_updated': last_updated
            })
        except Exception as e:
            flash(f"Error decrypting password for {site_url}: {e}", 'danger')
    
    return render_template('passwords.html',username=session['username'], passwords=passwords)

@app.route('/add_password', methods=['GET', 'POST'])
@login_required
def add_password():
    if request.method == 'POST':
        site_url = request.form['site_url']
        site_username = request.form['site_username']
        password = request.form['password']
        notes = request.form['notes']
        
        if 'master_password' not in session:
            flash('Session expired, please login again', 'danger')
            return redirect(url_for('login'))
        
        aes_key = derive_aes_key(session['master_password'], session['salt'])
        encrypted_password, per_entry_salt = encrypt(password, aes_key)
        
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO passwords (user_id, site_url, site_username, encrypted_password, entry_salt, notes, created_at, last_updated)"
                " VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                (session['user_id'], site_url, site_username, encrypted_password, per_entry_salt, notes)
            )
            conn.commit()
        
        flash('Password added successfully!', 'success')
        return redirect(url_for('view_passwords'))
    
    return render_template('add_password.html',username=session['username'])

@app.route('/generate_password')
@login_required
def generate_password_route():
    length = request.args.get('length', 16, type=int)
    password = generate_password(length)
    return password

@app.route('/public_password_generator')
def public_password_generator():
    return render_template('public_password_generator.html')

@app.route('/public_generate_password')
def public_generate_password():
    length = request.args.get('length', 16, type=int)
    if length < 8:
        length = 8
    elif length > 64:
        length = 64
    password = generate_password(length)
    return password

@app.route('/edit_password/<int:password_id>', methods=['GET', 'POST'])
@login_required
def edit_password(password_id):
    if 'master_password' not in session:
        flash('Session expired, please login again', 'danger')
        return redirect(url_for('login'))
    
    aes_key = derive_aes_key(session['master_password'], session['salt'])
    
    # Get the password entry
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute(
            "SELECT site_url, site_username, encrypted_password, entry_salt, notes FROM passwords WHERE password_id = ? AND user_id = ?",
            (password_id, session['user_id'])
        )
        entry = c.fetchone()
        
        if not entry:
            flash('Password not found', 'danger')
            return redirect(url_for('view_passwords'))
        
        site_url, site_username, encrypted_password, entry_salt, notes = entry
        decrypted_password = decrypt(encrypted_password, aes_key, entry_salt)
    
    if request.method == 'POST':
        # Update password
        new_site_url = request.form['site_url']
        new_site_username = request.form['site_username']
        new_password = request.form['password']
        new_notes = request.form['notes']
        
        # Insert old password into history
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO password_history (password_id, encrypted_password, entry_salt, changed_at)"
                " VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                (password_id, encrypted_password, entry_salt)
            )
            conn.commit()
        
        # Encrypt and update the new password
        new_encrypted_password, new_entry_salt = encrypt(new_password, aes_key)
        
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute(
                "UPDATE passwords SET site_url = ?, site_username = ?, encrypted_password = ?, entry_salt = ?, "
                "notes = ?, last_updated = CURRENT_TIMESTAMP WHERE password_id = ?",
                (new_site_url, new_site_username, new_encrypted_password, new_entry_salt, new_notes, password_id)
            )
            conn.commit()
        
        flash('Password updated successfully!', 'success')
        return redirect(url_for('view_passwords'))
    
    return render_template('edit_password.html', 
                           password={
                               'id': password_id,
                               'site_url': site_url,
                               'username': site_username,
                               'password': decrypted_password,
                               'notes': notes
                           })

@app.route('/delete_password/<int:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM passwords WHERE password_id = ? AND user_id = ?", 
                  (password_id, session['user_id']))
        conn.commit()
    
    flash('Password deleted successfully!', 'success')
    return redirect(url_for('view_passwords'))

@app.route('/password_history/<int:password_id>')
@login_required
def password_history(password_id):
    if 'master_password' not in session:
        flash('Session expired, please login again', 'danger')
        return redirect(url_for('login'))
    
    aes_key = derive_aes_key(session['master_password'], session['salt'])
    
    # Check if password belongs to user
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT site_url FROM passwords WHERE password_id = ? AND user_id = ?", 
                  (password_id, session['user_id']))
        site_data = c.fetchone()
        
        if not site_data:
            flash('Password not found', 'danger')
            return redirect(url_for('view_passwords'))
        
        site_url = site_data[0]
        
        # Get password history
        c.execute(
            "SELECT history_id, encrypted_password, entry_salt, changed_at FROM password_history "
            "WHERE password_id = ? ORDER BY changed_at DESC",
            (password_id,)
        )
        history_data = c.fetchall()
    
    history = []
    for entry in history_data:
        history_id, encrypted_password, entry_salt, changed_at = entry
        try:
            decrypted_password = decrypt(encrypted_password, aes_key, entry_salt)
            history.append({
                'id': history_id,
                'password': decrypted_password,
                'changed_at': changed_at
            })
        except Exception as e:
            flash(f"Error decrypting historical password: {e}", 'danger')
    
    return render_template('password_history.html', site_url=site_url, history=history)

if __name__ == '__main__':
    app.run(debug=True)  # Run the Flask app on port 5000