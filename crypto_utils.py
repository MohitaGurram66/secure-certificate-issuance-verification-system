from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os

KEY_DIR = 'keys'
PRIVATE_KEY_FILE = os.path.join(KEY_DIR, 'private_key.pem')
PUBLIC_KEY_FILE = os.path.join(KEY_DIR, 'public_key.pem')
AES_KEY_FILE = os.path.join(KEY_DIR, 'aes_key.key')

def generate_keys():
    """Generates RSA Key Pair for Digital Signatures and AES Key for Encryption if not exist."""
    # RSA Keys
    if not os.path.exists(PRIVATE_KEY_FILE):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        with open(PRIVATE_KEY_FILE, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(PUBLIC_KEY_FILE, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    # AES Key
    if not os.path.exists(AES_KEY_FILE):
        key = Fernet.generate_key()
        with open(AES_KEY_FILE, 'wb') as f:
            f.write(key)

def load_private_key():
    with open(PRIVATE_KEY_FILE, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def load_public_key():
    with open(PUBLIC_KEY_FILE, 'rb') as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

def load_aes_key():
    with open(AES_KEY_FILE, 'rb') as f:
        return f.read()

# --- Digital Signature ---
def sign_data(data: str) -> bytes:
    """ signs string data using RSA Private Key """
    private_key = load_private_key()
    signature = private_key.sign(
        data.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(data: str, signature: bytes) -> bool:
    """ Verify signature using RSA Public Key """
    public_key = load_public_key()
    try:
        public_key.verify(
            signature,
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification Failed: {e}")
        return False

# --- AES Encryption ---
def encrypt_data(data: str) -> bytes:
    key = load_aes_key()
    f = Fernet(key)
    return f.encrypt(data.encode('utf-8'))

def decrypt_data(encrypted_data: bytes) -> str:
    key = load_aes_key()
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode('utf-8')
