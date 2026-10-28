import sqlite3
import base64
from crypto_utils import verify_signature
from models import Certificate
from app import create_app

app = create_app()

with app.app_context():
    # Fetch the latest certificate (ID 5 or whatever is latest)
    cert = Certificate.query.order_by(Certificate.id.desc()).first()
    
    if not cert:
        print("No certificate found")
        exit()

    print(f"Checking Certificate ID: {cert.id}")
    print(f"Student Name: {cert.student_name}")
    
    # Reconstruct data
    expiry_str = str(cert.expiry_date) if cert.expiry_date else "None"
    data_to_verify = f"{cert.student_name}|{cert.student_email}|{cert.course_name}|{cert.issue_date.isoformat()}|{expiry_str}"
    
    print(f"Data to Verify: {data_to_verify}")
    
    signature_bytes = base64.b64decode(cert.digital_signature)
    
    # Verify
    is_valid = verify_signature(data_to_verify, signature_bytes)
    print(f"Is Signature Valid? {is_valid}")
