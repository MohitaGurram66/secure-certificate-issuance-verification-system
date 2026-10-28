from app import create_app, db
from models import User
from werkzeug.security import generate_password_hash
import pyotp

# Ensure we are in the correct context
import sys
import os
sys.path.append(os.getcwd())

app = create_app()

with app.app_context():
    db.drop_all()
    db.create_all()
    
    # Check if admin exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@securecert.com',
            password_hash=generate_password_hash('admin123', method='scrypt'),
            role='admin',
            mfa_secret=pyotp.random_base32()
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin user created (username: admin, password: admin123)")
        print(f"Admin MFA Secret: {admin.mfa_secret}")
    else:
        print("Admin user already exists.")

    # Create Issuer
    if not User.query.filter_by(username='issuer').first():
        issuer = User(
            username='issuer',
            email='issuer@securecert.com',
            password_hash=generate_password_hash('issuer123', method='scrypt'),
            role='issuer',
            mfa_secret='JBSWY3DPEHPK3PXP' # Known secret for testing: 'JBSWY3DPEHPK3PXP' -> 486576 (example, but we need dynamic generation if we want valid TOTP. Actually, fixed secret allows us to generate TOTP in browser agent if it supports python exec, but it doesn't. We'll stick to manual or simple python requests for MFA if browser fails. But wait, I can calculate TOTP here and paste it?)
            # Actually, better to just use random and print it, then I can read the output.
            # OR better: I'll use a fixed secret 'JBSWY3DPEHPK3PXP' (Test Secret)
        )
        db.session.add(issuer)
        db.session.commit()
        print(f"Issuer created. Secret: {issuer.mfa_secret}")

    # Create Student
    if not User.query.filter_by(username='student').first():
        student = User(
            username='student',
            email='student@test.com',
            password_hash=generate_password_hash('student123', method='scrypt'),
            role='user',
            mfa_secret='JBSWY3DPEHPK3PXP'
        )
        db.session.add(student)
        db.session.commit()
        print(f"Student created. Secret: {student.mfa_secret}")

    print("Database initialized successfully.")
