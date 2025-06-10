from flask import Flask, request, redirect, session, url_for, render_template_string
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask import send_from_directory
import secrets
import re
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# MongoDB connection with error handling
try:
    client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
    client.admin.command('ismaster')
    db = client['chatdb']
    users = db['users']
    tokens = db['tokens']
    
    users.create_index("username", unique=True)
    users.create_index("email", unique=True)
    tokens.create_index("expires_at", expireAfterSeconds=0)
    
    logger.info("MongoDB connection established successfully")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {e}")
    raise

# Input validation
def validate_input(username, email, password, confirm_password=None):
    errors = []
    
    if username and (not (3 <= len(username) <= 20) or not re.match(r'^[a-zA-Z0-9_]+$', username)):
        errors.append("Username must be 3-20 characters, letters, numbers, or underscores")
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not email or not re.match(email_pattern, email) or len(email) > 254:
        errors.append("Invalid email format")
    
    if password and (len(password) < 8 or len(password) > 128 or
                    not re.search(r'[A-Z]', password) or
                    not re.search(r'[a-z]', password) or
                    not re.search(r'\d', password) or
                    not re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):
        errors.append("Password must be 8-128 characters with uppercase, lowercase, number, and special character")
    
    if confirm_password is not None and password != confirm_password:
        errors.append("Passwords do not match")
    
    if errors:
        return False, "; ".join(errors)
    return True, None

# Load HTML files
def load_html(file_name):
    try:
        with open(file_name, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        logger.error(f"Template file {file_name} not found")
        return "Template not found"
    except Exception as e:
        logger.error(f"Error loading template {file_name}: {e}")
        return "Template error"

# Authentication required decorator
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/<filename>')
def serve_static_file(filename):
    if filename.endswith(('.jpg', '.jpeg', '.png', '.gif', '.css', '.js')):
        return send_from_directory('.', filename)
    return "File type not allowed", 403

@app.route('/')
@login_required
def home():
    return render_template_string(load_html('index.html'), username=session['username'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')

            # Log form data for debugging
            logger.debug(f"Registration attempt: username={username}, email={email}")

            is_valid, error = validate_input(username, email, password, confirm_password)
            if not is_valid:
                logger.warning(f"Validation failed: {error}")
                return render_template_string(load_html('register.html'), error=error), 400

            if users.find_one({'$or': [{'username': username}, {'email': email}]}):
                logger.warning(f"Duplicate username or email: {username}, {email}")
                return render_template_string(load_html('register.html'), error="Username or email already exists"), 400

            hashed_pw = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
            users.insert_one({
                'username': username,
                'email': email,
                'password': hashed_pw,
                'created_at': datetime.utcnow(),
                'failed_attempts': 0,
                'locked_until': None,
                'last_login': None
            })
            logger.info(f"New user registered: {username}")
            return render_template_string(load_html('login.html'), message="Registration successful. Please login."), 201
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return render_template_string(load_html('register.html'), error="Registration failed"), 500
    return render_template_string(load_html('register.html'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')

            if not username or not password:
                return render_template_string(load_html('login.html'), error="Username and password required"), 400

            user = users.find_one({'username': username})
            
            if user and user.get('locked_until') and user['locked_until'] > datetime.utcnow():
                return render_template_string(load_html('login.html'), error=f"Account locked until {user['locked_until']}"), 403

            if user and check_password_hash(user['password'], password):
                users.update_one(
                    {'username': username},
                    {'$set': {
                        'failed_attempts': 0,
                        'locked_until': None,
                        'last_login': datetime.utcnow()
                    }}
                )
                session['username'] = username
                session.permanent = True
                logger.info(f"User logged in: {username}")
                
                next_url = request.form.get('next') or url_for('home')
                if not next_url.startswith('/'):
                    next_url = url_for('home')
                return redirect(next_url)
            
            if user:
                failed_attempts = user.get('failed_attempts', 0) + 1
                update_data = {'failed_attempts': failed_attempts}
                if failed_attempts >= 5:
                    update_data['locked_until'] = datetime.utcnow() + timedelta(minutes=15)
                    logger.warning(f"Account locked: {username}")
                users.update_one({'username': username}, {'$set': update_data})
                return render_template_string(load_html('login.html'), error="Invalid credentials"), 401
            
            return render_template_string(load_html('login.html'), error="Invalid credentials"), 401
        except Exception as e:
            logger.error(f"Login error: {e}")
            return render_template_string(load_html('login.html'), error="Login failed"), 500
    return render_template_string(load_html('login.html'), next=request.args.get('next', ''))

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')

            if not email:
                return render_template_string(load_html('forgot.html'), error="Email required"), 400

            is_valid, error = validate_input(None, email, password, confirm_password)
            if not is_valid:
                return render_template_string(load_html('forgot.html'), error=error), 400

            user = users.find_one({'email': email})
            if not user:
                return render_template_string(load_html('forgot.html'), error="Email not found"), 404

            hashed_pw = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
            users.update_one(
                {'email': email},
                {'$set': {
                    'password': hashed_pw,
                    'failed_attempts': 0,
                    'locked_until': None
                }}
            )
            logger.info(f"Password reset for: {email}")
            return render_template_string(load_html('login.html'), message="Password reset successful. Please login.")
        except Exception as e:
            logger.error(f"Forgot password error: {e}")
            return render_template_string(load_html('forgot.html'), error="Request failed"), 500
    return render_template_string(load_html('forgot.html'))

@app.route('/logout')
@login_required
def logout():
    username = session.get('username')
    session.clear()
    if username:
        logger.info(f"User logged out: {username}")
    return redirect(url_for('login'))

@app.errorhandler(404)
def not_found(error):
    return render_template_string(load_html('error.html'), error="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template_string(load_html('error.html'), error="Internal server error"), 500

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)