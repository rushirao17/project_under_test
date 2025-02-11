import boto3
import pandas as pd
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO
import sqlite3
import os
from dotenv import load_dotenv


app = Flask(__name__)

app.config['SECRET_KEY'] = 'FLASK_SECRET_KEY1'


load_dotenv()

S3_BUCKET = os.getenv("S3_BUCKET")
S3_BUCKET_Marker = os.getenv("S3_BUCKET_MARKER")
S3_REGION = os.getenv("S3_REGION")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_SESSION_TOKEN = os.getenv("AWS_SESSION_TOKEN")

# Initialize the S3 client with environment variables
s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    aws_session_token=AWS_SESSION_TOKEN,
    region_name=S3_REGION
)

FILE_TYPES = ["DAC", "DBDA", "Registration", "MasterData", "Placement"]
ALLOWED_EXTENSIONS = {".csv", ".xlsx", ".xls"}

# Database setup for user authentication
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Utility functions
def allowed_file(filename):
    return "." in filename and ("." + filename.rsplit(".", 1)[-1].lower()) in ALLOWED_EXTENSIONS

def is_logged_in():
    return "logged_in" in session and session["logged_in"]

@app.route('/')
def index():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('upload.html')

# User registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('register.html')

        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            conn.close()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different one.', 'error')

    return render_template('register.html')

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['logged_in'] = True
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

# File upload handling
@app.route('/upload', methods=['POST'])
def upload_files():
    if not is_logged_in():
        return redirect(url_for('login'))

    batch_month = request.form.get('batch_month')
    batch_year = request.form.get('batch_year')
    if not batch_month or not batch_year:
        return jsonify({"error": "Batch month and year are required"}), 400

    batch_name = f"{batch_month}_{batch_year}"
    uploaded_files = {}

    for file_type in FILE_TYPES:
        file = request.files.get(file_type)
        if not file:
            return jsonify({"error": f"Missing file: {file_type}"}), 400

        file_ext = "." + file.filename.rsplit(".", 1)[-1].lower()
        if file_ext not in ALLOWED_EXTENSIONS:
            return jsonify({"error": f"{file_type} file must be in .csv, .xlsx, or .xls format"}), 400

        try:
            # Processing for MasterData and Placement files
            if file_type in {"MasterData", "Placement"}:
                dac_sheet_name = request.form.get(f"{file_type}_DAC")
                dbda_sheet_name = request.form.get(f"{file_type}_DBDA")

                df = pd.read_excel(file, sheet_name=None)

                if dac_sheet_name not in df or dbda_sheet_name not in df:
                    return jsonify({"error": f"Incorrect sheet names for {file_type}"}), 400

                # DAC sheet processing
                dac_buffer = BytesIO()
                df[dac_sheet_name].to_csv(dac_buffer, index=False)
                dac_buffer.seek(0)
                dac_key = f"{batch_name}/{file_type}_DAC.csv"
                s3_client.upload_fileobj(dac_buffer, S3_BUCKET, dac_key)
                uploaded_files[f"{file_type}_DAC"] = dac_key

                # DBDA sheet processing
                dbda_buffer = BytesIO()
                df[dbda_sheet_name].to_csv(dbda_buffer, index=False)
                dbda_buffer.seek(0)
                dbda_key = f"{batch_name}/{file_type}_DBDA.csv"
                s3_client.upload_fileobj(dbda_buffer, S3_BUCKET, dbda_key)
                uploaded_files[f"{file_type}_DBDA"] = dbda_key
            else:
                # Processing other files
                buffer = BytesIO()
                pd.read_excel(file).to_csv(buffer, index=False)
                buffer.seek(0)
                s3_key = f"{batch_name}/{file_type}.csv"
                s3_client.upload_fileobj(buffer, S3_BUCKET, s3_key)

                uploaded_files[file_type] = s3_key

        except Exception as e:
            return jsonify({"error": f"Error processing {file_type}: {str(e)}"}), 500

    return jsonify({"message": "Files uploaded successfully", "files": uploaded_files}), 200

if __name__ == '__main__':
    app.run(debug=True)
