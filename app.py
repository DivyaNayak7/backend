from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import os
import jwt
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

# Hardcoded secret key (VULNERABILITY)
app.config['SECRET_KEY'] = 'weak-secret-key'  

# SQLAlchemy database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///learning.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Insecure file upload directory (VULNERABILITY: No file validation)
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)

# Define Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)  # VULNERABILITY: Plaintext Password
    role = db.Column(db.String(20), nullable=False)  # 'student' or 'teacher'

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)  # VULNERABILITY: Stored XSS Possible
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    enrolled_at = db.Column(db.DateTime, default=datetime.utcnow)

# SQL Injection Vulnerability
@app.route('/api/unsafe-login', methods=['POST'])
def unsafe_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Direct SQL Query (VULNERABILITY)
    connection = sqlite3.connect('learning.db')
    cursor = connection.cursor()
    query = f"SELECT * FROM user WHERE username='{username}' AND password='{password}'"  
    cursor.execute(query)  # VULNERABLE: No input sanitization
    user = cursor.fetchone()
    connection.close()

    if user:
        return jsonify({'message': 'Login Successful'})
    return jsonify({'message': 'Invalid Credentials'}), 401

# Insecure File Upload (VULNERABILITY)
@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'No file provided'}), 400

    file = request.files['file']
    filename = secure_filename(file.filename)

    # VULNERABILITY: Allowing all file types without checking
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    return jsonify({'message': 'File uploaded successfully', 'filename': filename})

# Insecure File Download (VULNERABILITY: Path Traversal)
@app.route('/api/download/<path:filename>', methods=['GET'])
def download_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))  # No path validation

# No Authentication Check (VULNERABILITY)
@app.route('/api/courses', methods=['GET'])
def get_courses():
    courses = Course.query.all()
    return jsonify([{'id': c.id, 'title': c.title, 'description': c.description} for c in courses])

# Start Application
if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    with app.app_context():
        db.create_all()

    app.run(debug=True, host='0.0.0.0', port=4000)
