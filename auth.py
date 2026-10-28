from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from extensions import db
from models import User
from decorators import role_required
import pyotp
import qrcode
import io
import base64

auth = Blueprint('auth', __name__, url_prefix='/auth')

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        admin_code = request.form.get('admin_code')

        # Check Username
        if User.query.filter_by(username=username).first():
            flash(f'Username "{username}" is already taken. Please choose another.', 'danger')
            return redirect(url_for('auth.register'))
        
        # Check Email
        if User.query.filter_by(email=email).first():
            flash(f'Email "{email}" is already registered. Please login.', 'danger')
            return redirect(url_for('auth.register'))

        # LAB REQUIREMENT: Hashing with Salt (Werkzeug handles salt automatically)
        hashed_pw = generate_password_hash(password, method='scrypt')
        print(f"DEBUG: Registering user {username} with hash: {hashed_pw}") # DEBUG

        new_user = User(
            username=username, 
            email=email,
            password_hash=hashed_pw,
            role=role,
            mfa_secret=pyotp.random_base32() 
        )

        db.session.add(new_user)
        db.session.commit()
        print(f"DEBUG: User {username} committed to DB.") # DEBUG

        flash('Registration successful! Please setup MFA.')
        return redirect(url_for('auth.setup_mfa', user_id=new_user.id))

    return render_template('register.html')

@auth.route('/setup-mfa/<int:user_id>')
def setup_mfa(user_id):
    user = User.query.get_or_404(user_id)
    #  Encoding (QR Code)
    totp = pyotp.TOTP(user.mfa_secret)
    uri = totp.provisioning_uri(name=user.username, issuer_name="SecureCertApp")
    
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf)
    img_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    
    return render_template('setup_mfa.html', img_b64=img_b64, secret=user.mfa_secret, user=user)

@auth.route('/skip-mfa/<int:user_id>')
def skip_mfa(user_id):
    user = User.query.get_or_404(user_id)
    # Remove the secret to disable MFA
    user.mfa_secret = None
    db.session.commit()
    flash('MFA setup skipped. You can enable it later in settings.', 'info')
    return redirect(url_for('auth.login'))

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form.get('username')
        password = request.form.get('password')
        
        print(f"DEBUG: Attempting login for {username_or_email}") # DEBUG

        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
        
        if user:
            print(f"DEBUG: User found: {user.username}, Role: {user.role}") # DEBUG
            is_valid = check_password_hash(user.password_hash, password)
            print(f"DEBUG: Password valid? {is_valid}") # DEBUG
        else:
            print("DEBUG: User NOT found") # DEBUG

        #Authentication (Password)
        if not user or not check_password_hash(user.password_hash, password):
            flash('Please check your login details and try again.', 'danger') 
            return redirect(url_for('auth.login'))

        # Check if MFA is enabled
        if user.mfa_secret:
            # Proceed to MFA Step
            session['pre_auth_user_id'] = user.id
            return redirect(url_for('auth.mfa_verify'))
        else:
            # No MFA, login directly
            login_user(user)
            return redirect(url_for('index'))

    return render_template('login.html')

@auth.route('/mfa-verify', methods=['GET', 'POST'])
def mfa_verify():
    if 'pre_auth_user_id' not in session:
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        user = User.query.get(session['pre_auth_user_id'])
        
        totp = pyotp.TOTP(user.mfa_secret)
        #  Multi-Factor Authentication
        if totp.verify(otp):
            login_user(user)
            session.pop('pre_auth_user_id', None)
            return redirect(url_for('index'))
        else:
            flash('Invalid OTP')
            
    return render_template('mfa_verify.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@auth.route('/admin/users')
@login_required
@role_required('admin')
def manage_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@auth.route('/admin/user/<int:user_id>/role', methods=['POST'])
@login_required
@role_required('admin')
def update_user_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    if new_role not in ['admin', 'issuer', 'verifier', 'user']:
        flash('Invalid role selected.')
    else:
        user.role = new_role
        db.session.commit()
        flash(f'User {user.username} role updated to {new_role}.')
    return redirect(url_for('auth.manage_users'))

@auth.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        flash('Cannot delete the main Admin account.', 'danger')
    else:
        username = user.username
        db.session.delete(user)
        db.session.commit()
        flash(f'User {username} has been deleted.', 'success')
    return redirect(url_for('auth.manage_users'))
