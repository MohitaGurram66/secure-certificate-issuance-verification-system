# 🔐 Secure Certificate Issuance & Verification System

A secure web application that issues, signs, and verifies digital certificates using modern cryptographic techniques.

---

## 🎯 Objective

To prevent certificate forgery and tampering by combining:
- Cryptographic hashing
- Symmetric & asymmetric encryption
- Digital signatures
- Multi-factor authentication

---

## 🧱 Tech Stack

- Backend: Python (Flask)
- Database: SQLite
- Frontend: HTML5, Bootstrap 5
- Security: cryptography, pyotp, werkzeug

---

## 🔐 Security Features

### Authentication
- scrypt password hashing
- Salted hashes stored in DB

### Multi-Factor Authentication
- TOTP-based MFA using pyotp
- QR-based secret provisioning

### Authorization
- Role-based access control (Admin, Issuer, Verifier, Student)

### Confidentiality
- AES-128 encryption (Fernet) for private certificate fields

### Integrity & Authenticity
- RSA-2048 digital signatures
- Public key verification

---

## 🧪 Tamper Detection

A dedicated script (`tamper_data.py`) modifies certificate data directly in the database.
Since the signature is unchanged, verification fails — proving tamper resistance.

---

## 📄 Secure PDF Certificates

- Generated using ReportLab
- Embedded QR code for verification
- Digitally signed watermark

---

## ⚙️ Installation

```bash
git clone https://github.com/YOUR_USERNAME/secure-certificate-issuance-verification-system.git
cd secure-certificate-issuance-verification-system
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
