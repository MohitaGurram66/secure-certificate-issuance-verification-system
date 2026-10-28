from extensions import db, login_manager
from flask_login import UserMixin
from datetime import datetime
import uuid

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False) # Stores bcrypt hash
    role = db.Column(db.String(20), nullable=False) # 'admin', 'issuer', 'student'
    mfa_secret = db.Column(db.String(32)) # For TOTP

class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    unique_certificate_id = db.Column(db.String(36), default=lambda: str(uuid.uuid4()), unique=True, nullable=False)
    student_name = db.Column(db.String(100), nullable=False)
    student_email = db.Column(db.String(120), nullable=False) # Link to user
    course_name = db.Column(db.String(100), nullable=False)
    issue_date = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime, nullable=True) 
    is_revoked = db.Column(db.Boolean, default=False)
    
    # Encrypted fields
    encrypted_data = db.Column(db.LargeBinary) # Stores AES encrypted sensitive data
    # Signature
    digital_signature = db.Column(db.String(500)) # Stores the RSA signature 
    # Issuer
    issuer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
