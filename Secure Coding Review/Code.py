from flask import Flask, request, jsonify
import sqlite3
import bcrypt
from marshmallow import Schema, fields, ValidationError
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Set up rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["5 per minute"]  # Set default rate limits for all routes
)

# Database connection function
def get_db_connection():
    conn = sqlite3.connect(os.environ.get('DATABASE_URL', 'database.db'))
    conn.row_factory = sqlite3.Row
    return conn

# Schema for user validation
class UserSchema(Schema):
    username = fields.Str(required=True, validate=lambda p: len(p) >= 3)  # Username must be at least 3 characters
    password = fields.Str(required=True, validate=lambda p: len(p) >= 8)  # Password must be at least 8 characters

@app.route('/')
def show():
    return "Hello"

@app.route('/users', methods=['GET'])
@limiter.limit("5 per minute")  # Specific rate limit for this route
def get_users():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username FROM users').fetchall()  # Exclude password from the query
    conn.close()
    return jsonify([dict(user) for user in users])

@app.route('/user', methods=['POST'])
@limiter.limit("5 per minute")
def create_user():
    username = request.args.get('username')  # Get username from query parameters
    password = request.args.get('password')  # Get password from query parameters
    
    # Validate input
    if not username or len(username) < 3:
        return jsonify({'error': 'Invalid username'}), 400
    if not password or len(password) < 8:
        return jsonify({'error': 'Invalid password'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists.'}), 400
    finally:
        conn.close()

    return jsonify({'status': 'success'}), 201

def init_db():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )''')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', debug=True, ssl_context='adhoc')
