from cryptography.fernet import Fernet
from flask import Flask, request, render_template, redirect, url_for, session, flash
import bcrypt
import sqlite3
import os
import random
import string

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# ---------- DATABASE INITIALIZATION ----------

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Users (
            UserID INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT NOT NULL UNIQUE,
            PasswordHash TEXT NOT NULL,
            CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Password Entries
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS PasswordEntry (
            EntryID INTEGER PRIMARY KEY AUTOINCREMENT,
            UserID INTEGER NOT NULL,
            ServiceName TEXT NOT NULL,
            EncryptedPassword TEXT NOT NULL,
            CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(UserID) REFERENCES Users(UserID)
        )
    ''')

    # Encryption Keys
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS EncryptionKeys (
            KeyID INTEGER PRIMARY KEY AUTOINCREMENT,
            KeyValue TEXT NOT NULL,
            UserID INTEGER UNIQUE NOT NULL,
            FOREIGN KEY(UserID) REFERENCES Users(UserID)
        )
    ''')

    conn.commit()
    conn.close()

# ---------- HELPER FUNCTIONS ----------

def get_user_from_db(username):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Users WHERE Username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            'username': row[1],      # Username
            'password': row[2]       # PasswordHash
        }
    return None

def generate_strong_password(length=12):
    characters = string.ascii_letters + string.digits + "!@#$%^&*()-_+="
    return ''.join(random.choice(characters) for _ in range(length))

def get_user_id(username):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT UserID FROM Users WHERE Username = ?", (username,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

def create_encryption_key(user_id):
    if not user_id:
        raise ValueError("❌ User ID missing when creating key")
    
    key = Fernet.generate_key()
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO EncryptionKeys (KeyValue, UserID) VALUES (?, ?)", (key.decode(), user_id))
    conn.commit()
    conn.close()

def load_key(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT KeyValue FROM EncryptionKeys WHERE UserID = ?", (user_id,))
    result = c.fetchone()
    conn.close()

    if not result:
        raise ValueError(f"Encryption key not found for user ID {user_id}")
    return result[0].encode()

def save_password(user_id, label, password):
    key = load_key(user_id)
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO PasswordEntry (UserID, ServiceName, EncryptedPassword) VALUES (?, ?, ?)",
              (user_id, label, encrypted_password))
    conn.commit()
    conn.close()

def retrieve_password(user_id, label):
    key = load_key(user_id)
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT EncryptedPassword FROM PasswordEntry WHERE UserID = ? AND ServiceName = ?", (user_id, label))
    row = c.fetchone()
    conn.close()

    if row:
        fernet = Fernet(key)
        return fernet.decrypt(row[0]).decode()
    return "Password not found."

def verify_user(username, password):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT PasswordHash FROM Users WHERE Username = ?", (username,))
    result = c.fetchone()
    conn.close()

    if result and bcrypt.checkpw(password.encode(), result[0]):
        return True
    return False

# ---------- FLASK ROUTES ----------

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        try:
            c.execute("INSERT INTO Users (Username, PasswordHash) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            c.execute("SELECT UserID FROM Users WHERE Username = ?", (username,))
            user_id = c.fetchone()[0]
            create_encryption_key(user_id)
            conn.close()

            # ✅ FLASH FIRST, THEN REDIRECT
            flash("✅ Account created successfully! Please log in.")
            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            conn.close()
            flash("⚠️ Username already exists.")
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # check credentials logic here
        user = get_user_from_db(username)
        if user and bcrypt.checkpw(password.encode(), user['password']):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('❌ Invalid username or password')
            return redirect(url_for('login'))  # redirects back to login with message

    return render_template('login.html')

@app.route('/delete_account', methods=['POST'])
def delete_account():
    username = request.form['username']  # comes from the login page form
    user_id = get_user_id(username)

    if not user_id:
        flash("❌ Username does not exist.")
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("DELETE FROM PasswordEntry WHERE UserID = ?", (user_id,))
    c.execute("DELETE FROM EncryptionKeys WHERE UserID = ?", (user_id,))
    c.execute("DELETE FROM Users WHERE UserID = ?", (user_id,))
    conn.commit()
    conn.close()

    flash("✅ Account deleted successfully.")
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/generate_password', methods=['GET', 'POST'])
def generate_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        label = request.form['label']
        length = int(request.form.get('length', 12))  #Get length from form, default 12

        user_id = get_user_id(session['username'])
        password = generate_strong_password(length)
        save_password(user_id, label, password)

        return render_template('generated_password.html', password=password)

    return render_template('generate.html')


@app.route('/retrieve_password', methods=['GET', 'POST'])
def retrieve_password_view():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        label = request.form['label']
        user_id = get_user_id(session['username'])
        password = retrieve_password(user_id, label)
        return render_template('retrieve.html', password=password)

    return render_template('retrieve.html')

@app.route('/delete_password', methods=['POST'])
def delete_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    label = request.form['label']
    user_id = get_user_id(session['username'])

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("DELETE FROM PasswordEntry WHERE UserID = ? AND ServiceName = ?", (user_id, label))
    conn.commit()
    conn.close()

    return render_template('retrieve.html', password=f"✅ Password for '{label}' deleted.")


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))



# ---------- APP ENTRY POINT ----------

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
