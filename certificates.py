from flask import Blueprint, render_template, redirect, url_for, request, flash, send_file
from flask_login import login_required, current_user
from extensions import db
from models import Certificate, User
from decorators import role_required
from crypto_utils import encrypt_data, decrypt_data, sign_data, verify_signature
import datetime
import base64
import qrcode
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
import textwrap
import socket

certificates = Blueprint('certificates', __name__, url_prefix='/certificates')

@certificates.route('/issue', methods=['GET', 'POST'])
@login_required
@role_required('issuer')
def issue_certificate():
    if request.method == 'POST':
        student_name = request.form.get('student_name')
        student_email = request.form.get('student_email')
        course_name = request.form.get('course_name')
        remarks = request.form.get('remarks')
        expiry_date_str = request.form.get('expiry_date')
        
        issue_date = datetime.datetime.utcnow()
        expiry_date = None
        if expiry_date_str:
            expiry_date = datetime.datetime.strptime(expiry_date_str, '%Y-%m-%d')

        # Data to sign (Name + Email + Course + IssueDate + ExpiryDate)
        # We include Email and Expiry to bind them to the signature integrity
        expiry_str = str(expiry_date) if expiry_date else "None"
        data_to_sign = f"{student_name}|{student_email}|{course_name}|{issue_date.isoformat()}|{expiry_str}"
        
        print(f"DEBUG ISSUE: Data signing: {data_to_sign}") 
        # LAB REQUIREMENT: Digital Signature
        signature = sign_data(data_to_sign)
        signature_b64 = base64.b64encode(signature).decode('utf-8')

        # LAB REQUIREMENT: Encryption (AES)
        encrypted_remarks = encrypt_data(remarks)

        cert = Certificate(
            student_name=student_name,
            student_email=student_email,
            course_name=course_name,
            issue_date=issue_date,
            expiry_date=expiry_date,
            encrypted_data=encrypted_remarks,
            digital_signature=signature_b64,
            issuer_id=current_user.id
        )

        db.session.add(cert)
        db.session.commit()
        
        flash('Certificate Issued Successfully with Digital Signature!')
        return redirect(url_for('certificates.list_certificates'))

    return render_template('issue_certificate.html')

@certificates.route('/revoke/<int:cert_id>', methods=['POST'])
@login_required
def revoke_certificate(cert_id):
    if current_user.role != 'issuer':
        flash('Unauthorized action. Only Issuers can revoke certificates.')
        return redirect(url_for('certificates.list_certificates'))
        
    cert = Certificate.query.get_or_404(cert_id)
    cert.is_revoked = True
    db.session.commit()
    flash(f'Certificate for {cert.student_name} revoked.')
    return redirect(url_for('certificates.list_certificates'))

@certificates.route('/')
@login_required
def list_certificates():
    # Admin/Issuer sees all, User sees only theirs (matched by email)
    if current_user.role in ['admin', 'issuer', 'verifier']:
        certs = Certificate.query.all()
    else:
        # Assuming current_user has email field now
        certs = Certificate.query.filter_by(student_email=current_user.email).all()

    display_certs = []
    
    for cert in certs:
        # Decrypt remarks for display only allowed users
        remarks = "Encrypted"
        if current_user.role in ['admin', 'issuer'] or current_user.email == cert.student_email:
             try:
                 remarks = decrypt_data(cert.encrypted_data)
             except:
                 remarks = "Decryption Failed"
        
        # Fetch issuer name
        issuer_name = "Unknown"
        if cert.issuer_id:
             issuer_user = User.query.get(cert.issuer_id)
             if issuer_user:
                 issuer_name = issuer_user.username

        display_certs.append({
            'id': cert.id,
            'unique_id': cert.unique_certificate_id,
            'student_name': cert.student_name,
            'course_name': cert.course_name,
            'issue_date': cert.issue_date,
            'expiry_date': cert.expiry_date,
            'is_revoked': cert.is_revoked,
            'remarks': remarks,
            'signature': cert.digital_signature[:20] + "...",
            'issuer_name': issuer_name
        })
        
    return render_template('view_certificates.html', certificates=display_certs, now=datetime.datetime.utcnow())

@certificates.route('/verify/<int:cert_id>')
@login_required
def verify_certificate(cert_id):
    if current_user.role == 'student' or current_user.role == 'user':
        flash('Unauthorized. Students cannot access the verification tool.', 'danger')
        return redirect(url_for('certificates.list_certificates'))

    cert = Certificate.query.get_or_404(cert_id)
    
    # Reconstruct data to verify
    # Ensure consistent string formatting (handle None expiry same as Issue)
    expiry_str = str(cert.expiry_date) if cert.expiry_date else "None"
    data_to_verify = f"{cert.student_name}|{cert.student_email}|{cert.course_name}|{cert.issue_date.isoformat()}|{expiry_str}"
    
    print(f"DEBUG VERIFY: Data recovered: {data_to_verify}") # DEBUG
    
    signature_bytes = base64.b64decode(cert.digital_signature)
    
    #Signature Verification
    signature_valid = verify_signature(data_to_verify, signature_bytes)
    print(f"DEBUG VERIFY: Valid? {signature_valid}") # DEBUG
    
    # Check Revocation and Expiry
    is_revoked = cert.is_revoked
    is_expired = False
    now_utc = datetime.datetime.utcnow()
    if cert.expiry_date and cert.expiry_date < now_utc:
        is_expired = True
        
    is_valid = signature_valid and not is_revoked and not is_expired
    
    status_msg = "Valid"
    if not signature_valid: status_msg = "Invalid Signature (Tampered)"
    if is_revoked: status_msg = "Revoked"
    if is_expired: status_msg = "Expired"

    # Generate QR Code for this verification page
    #  Detect LAN IP for mobile scanning
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = '127.0.0.1'
        
    verify_url = url_for('certificates.verify_certificate', cert_id=cert.id, _external=True).replace('127.0.0.1', local_ip).replace('localhost', local_ip)
    
    qr = qrcode.make(verify_url)
    buf = io.BytesIO()
    qr.save(buf)
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render_template('verify_certificate.html', cert=cert, is_valid=is_valid, status_msg=status_msg, qr_code=qr_b64)

@certificates.route('/download/<int:cert_id>')
@login_required
def download_certificate(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    
    # Check access permission
    # Admin cannot download. Only Issuer or the Owner (Student)
    if current_user.role != 'issuer' and (not hasattr(current_user, 'email') or current_user.email != cert.student_email):
         flash('Unauthorized access to this certificate.')
         return redirect(url_for('certificates.list_certificates'))

    # Create PDF
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=landscape(letter))
    width, height = landscape(letter)

    # Design
    p.setStrokeColor(colors.darkblue)
    p.setLineWidth(5)
    p.rect(30, 30, width-60, height-60)
    
    p.setFont("Helvetica-Bold", 36)
    p.drawCentredString(width/2, height-100, "Certificate of Completion")
    
    p.setFont("Helvetica", 14)
    p.drawCentredString(width/2, height-140, "This is to certify that")
    
    p.setFont("Helvetica-BoldOblique", 28)
    p.drawCentredString(width/2, height-190, cert.student_name)
    
    p.setFont("Helvetica", 14)
    p.drawCentredString(width/2, height-230, "has successfully completed the course")
    
    p.setFont("Helvetica-Bold", 24)
    p.drawCentredString(width/2, height-270, cert.course_name)

    p.setFont("Helvetica", 12)
    p.drawString(100, 150, f"Date of Issue: {cert.issue_date.strftime('%Y-%m-%d')}")
    if cert.expiry_date:
        p.drawString(100, 130, f"Valid Until: {cert.expiry_date.strftime('%Y-%m-%d')}")
    
    p.drawString(100, 110, f"Certificate ID: {cert.unique_certificate_id}")
    
    # Verify URL QR Code
    # Detect LAN IP for mobile scanning
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = '127.0.0.1'

    verify_url = url_for('certificates.verify_certificate', cert_id=cert.id, _external=True).replace('127.0.0.1', local_ip).replace('localhost', local_ip)
    qr = qrcode.make(verify_url)
    qr_img = qr.get_image()
    
    # Save QR to temp buffer to draw on PDF
    qr_buffer = io.BytesIO()
    qr.save(qr_buffer)
    qr_buffer.seek(0)
    
    from reportlab.lib.utils import ImageReader
    p.drawImage(ImageReader(qr_buffer), width-150, 60, width=100, height=100)
    p.drawString(width-150, 50, "Scan to Verify")

    # Signature (Visual representation)
    p.setFont("Courier", 8)
    p.drawString(100, 95, "Digital Signature:")
    
    # Wrap signature text
    signature_text = cert.digital_signature
    wrapped_signature = textwrap.wrap(signature_text, width=110)
    
    y = 85
    p.setFont("Courier", 6) # Smaller font to fit everything
    for line in wrapped_signature: 
        p.drawString(100, y, line)
        y -= 8

    p.showPage()
    p.save()
    
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"Certificate_{cert.student_name}.pdf", mimetype='application/pdf')
