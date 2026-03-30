import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'eml', 'msg'}
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    
    # Email analysis settings
    SUSPICIOUS_KEYWORDS = [
        "urgent", "verify", "account", "security", "login", "password",
        "bank", "paypal", "suspended", "action required", "confirm"
    ]
    
    TRUSTED_DOMAINS = [
        "google.com", "microsoft.com", "apple.com", "amazon.com",
        "paypal.com", "linkedin.com", "facebook.com", "twitter.com"
    ]
    
    DANGEROUS_EXTENSIONS = [
        ".exe", ".bat", ".cmd", ".scr", ".ps1", ".js", ".vbs",
        ".jar", ".msi", ".pif", ".com", ".hta", ".reg", ".sh"
    ]
    
    # API Keys (replace with your actual keys)
    VIRUSTOTAL_API_KEY = os.environ.get("8445803baa0217d93437379d45d1c8a876ae488294adea2c61704a72b3fb2a75")
    ENABLE_VIRUSTOTAL = os.environ.get('ENABLE_VIRUSTOTAL', 'False').lower() == 'true'
