import sqlite3
import os

DB_PATH = 'instance/secure_cert.db'

if not os.path.exists(DB_PATH):
    print("DB not found")
    exit()

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

print(f"{'Username':<15} | {'Role':<10} | {'MFA Secret':<20} | {'Password Hash (First 20 chars)'}")
print("-" * 80)

cursor.execute("SELECT username, role, mfa_secret, password_hash FROM user")
rows = cursor.fetchall()

if not rows:
    print("No users found in database.")

for row in rows:
    username = row[0]
    role = row[1]
    mfa = row[2] if row[2] else "NONE (Skipped)"
    pwd_hash = row[3][:20] + "..." if row[3] else "EMPTY"
    
    print(f"{username:<15} | {role:<10} | {mfa:<20} | {pwd_hash}")

conn.close()
