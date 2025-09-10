import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-super-secret-key-change-this'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///auth.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Email Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('EMAIL_USER') or 'your-email@gmail.com'
    MAIL_PASSWORD = os.environ.get('EMAIL_PASS') or 'your-app-password'
    MAIL_DEFAULT_SENDER = os.environ.get('EMAIL_USER') or 'your-email@gmail.com'
    
    # Security Settings
    JWT_EXPIRATION_DELTA = timedelta(hours=24)
    RESET_TOKEN_EXPIRATION = timedelta(minutes=15)
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = "memory://"
