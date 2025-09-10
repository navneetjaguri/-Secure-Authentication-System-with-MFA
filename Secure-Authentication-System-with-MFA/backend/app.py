from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import qrcode
import io
import base64
from models import db, User, PasswordResetToken, LoginAttempt
from auth import generate_jwt_token, token_required
from config import Config
import re
import os

app = Flask(__name__, static_folder='../frontend', template_folder='../frontend')   
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
mail = Mail(app)
limiter = Limiter(app, default_limits=["1000 per hour"])
limiter.key_func = get_remote_address


def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_strong_password(password):
    return (len(password) >= 8 and 
            any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password))

def log_login_attempt(ip_address, username, success):
    attempt = LoginAttempt(ip_address=ip_address, username=username, success=success)
    db.session.add(attempt)
    db.session.commit()

def send_reset_email(user, token):
    try:
        msg = Message(
            'Password Reset Request',
            recipients=[user.email]
        )
        reset_url = f"http://localhost:5000/reset-password?token={token.token}"
        msg.body = f'''
        Hi {user.username},

        You requested a password reset. Click the link below to reset your password:
        {reset_url}

        This link will expire in 15 minutes.

        If you didn't request this, please ignore this email.
        '''
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# Routes
@app.route('/')
def index():
    return send_from_directory('../frontend', 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('../frontend', filename)

@app.route('/api/signup', methods=['POST'])
@limiter.limit("5 per minute")
def signup():
    data = request.get_json()
    
    if not data or not all(k in data for k in ['username', 'email', 'password']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    username = data['username'].strip()
    email = data['email'].strip().lower()
    password = data['password']
    
    # Validation
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    
    if not is_valid_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    if not is_strong_password(password):
        return jsonify({'error': 'Password must be at least 8 characters with uppercase, lowercase, number, and special character'}), 400
    
    # Check if user exists
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    # Create user
    user = User(username=username, email=email)
    user.set_password(password)
    user.generate_mfa_secret()
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User created successfully', 'user_id': user.id}), 201

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    ip_address = get_remote_address()
    
    if not data or not all(k in data for k in ['username', 'password']):
        return jsonify({'error': 'Missing username or password'}), 400
    
    username = data['username'].strip()
    password = data['password']
    
    user = User.query.filter_by(username=username).first()
    
    if not user or not user.check_password(password):
        log_login_attempt(ip_address, username, False)
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Check if MFA is enabled
    if user.mfa_enabled:
        log_login_attempt(ip_address, username, True)
        return jsonify({
            'message': 'MFA required',
            'mfa_required': True,
            'user_id': user.id
        }), 200
    
    # Generate token
    token = generate_jwt_token(user.id)
    log_login_attempt(ip_address, username, True)
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'username': user.username
    }), 200

@app.route('/api/verify-mfa', methods=['POST'])
@limiter.limit("10 per minute")
def verify_mfa():
    data = request.get_json()
    
    if not data or not all(k in data for k in ['user_id', 'totp_code']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    user = User.query.get(data['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if not user.verify_totp(data['totp_code']):
        return jsonify({'error': 'Invalid TOTP code'}), 401
    
    token = generate_jwt_token(user.id)
    
    return jsonify({
        'message': 'MFA verification successful',
        'token': token,
        'username': user.username
    }), 200

@app.route('/api/setup-mfa', methods=['POST'])
@token_required
def setup_mfa(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if not user.mfa_secret:
        user.generate_mfa_secret()
        db.session.commit()
    
    # Generate QR code
    qr_uri = user.get_totp_uri()
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_uri)
    qr.make(fit=True)
    
    qr_img = qr.make_image(fill_color="black", back_color="white")
    img_buffer = io.BytesIO()
    qr_img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    
    qr_code_data = base64.b64encode(img_buffer.getvalue()).decode()
    
    return jsonify({
        'qr_code': f"data:image/png;base64,{qr_code_data}",
        'secret': user.mfa_secret
    }), 200

@app.route('/api/enable-mfa', methods=['POST'])
@token_required
def enable_mfa(user_id):
    data = request.get_json()
    
    if not data or 'totp_code' not in data:
        return jsonify({'error': 'TOTP code required'}), 400
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if not user.verify_totp(data['totp_code']):
        return jsonify({'error': 'Invalid TOTP code'}), 401
    
    user.mfa_enabled = True
    db.session.commit()
    
    return jsonify({'message': 'MFA enabled successfully'}), 200

@app.route('/api/forgot-password', methods=['POST'])
@limiter.limit("3 per minute")
def forgot_password():
    data = request.get_json()
    
    if not data or 'email' not in data:
        return jsonify({'error': 'Email required'}), 400
    
    email = data['email'].strip().lower()
    user = User.query.filter_by(email=email).first()
    
    if user:
        # Delete existing tokens
        PasswordResetToken.query.filter_by(user_id=user.id, used=False).delete()
        
        # Create new token
        reset_token = PasswordResetToken(user.id)
        db.session.add(reset_token)
        db.session.commit()
        
        # Send email
        if send_reset_email(user, reset_token):
            return jsonify({'message': 'Password reset email sent'}), 200
        else:
            return jsonify({'error': 'Failed to send email'}), 500
    
    # Always return success to prevent email enumeration
    return jsonify({'message': 'If the email exists, a reset link has been sent'}), 200

@app.route('/api/reset-password', methods=['POST'])
@limiter.limit("5 per minute")
def reset_password():
    data = request.get_json()
    
    if not data or not all(k in data for k in ['token', 'password']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    token = PasswordResetToken.query.filter_by(token=data['token']).first()
    
    if not token or not token.is_valid():
        return jsonify({'error': 'Invalid or expired token'}), 400
    
    if not is_strong_password(data['password']):
        return jsonify({'error': 'Password must be at least 8 characters with uppercase, lowercase, number, and special character'}), 400
    
    user = User.query.get(token.user_id)
    user.set_password(data['password'])
    token.used = True
    
    db.session.commit()
    
    return jsonify({'message': 'Password reset successful'}), 200

@app.route('/api/dashboard', methods=['GET'])
@token_required
def dashboard(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'username': user.username,
        'email': user.email,
        'mfa_enabled': user.mfa_enabled,
        'created_at': user.created_at.isoformat()
    }), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
