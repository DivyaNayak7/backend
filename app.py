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

# 🚨 Hardcoded Secret Key (Vulnerability)
app.config['SECRET_KEY'] = 'super-secret-key'  # ❌ Exposed Secret Key

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///learning.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)

# 🚨 User Model with Plaintext Passwords
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)  # ❌ No Hashing
    role = db.Column(db.String(20), nullable=False)

# 🚨 Broken Authentication: SQL Injection in Login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    # ❌ SQL Injection: Direct user input in query
    query = f"SELECT * FROM user WHERE username='{data['username']}' AND password='{data['password']}'"
    user = db.session.execute(query).fetchone()  # ❌ SQL Injection risk!

    if user:
        token = jwt.encode({  # ❌ No Expiry
            'user_id': user.id,
            'username': user.username,
            'role': user.role
        }, app.config['SECRET_KEY'])
        return jsonify({'token': token})

    return jsonify({'message': 'Invalid credentials'}), 401

# 🚨 Insecure File Upload (No Validation)
@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'No file uploaded'}), 400

    file = request.files['file']

    # ❌ No validation of file type
    filename = file.filename  # ❌ Path Traversal risk
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    return jsonify({'message': 'File uploaded successfully'})

# 🚨 Insecure File Download (No Access Control)
@app.route('/api/download/<path:filename>', methods=['GET'])
def download_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))  # ❌ Unrestricted Access

# 🚨 Missing Authentication in User Registration
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400

    # ❌ Storing Passwords in Plaintext
    new_user = User(username=data['username'], password=data['password'], role=data['role'])

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Registration successful'})

# 🚨 JWT Tokens Never Expire (No Logout Mechanism)
@app.route('/api/token-test', methods=['GET'])
def token_test():
    token = request.headers.get('Authorization', '').split('Bearer ')[-1]
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({'message': 'Token is valid', 'user': payload})
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    with app.app_context():
        db.create_all()

    app.run(debug=True, host='0.0.0.0', port=4000)
