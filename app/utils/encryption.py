import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import base64

# Use a fixed salt for PBKDF2 key derivation for now.
# Ideally, each user should have a unique salt stored with their profile.
# We will address this when updating the User model.
# For key derivation, not encryption itself.
PBKDF2_ITERATIONS = 600000  # OWASP recommendation as of 2023

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit key from a password and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(password.encode('utf-8'))
    return key

def encrypt_data(key: bytes, plaintext: str) -> str:
    """Encrypts plaintext using AES-GCM and returns base64-encoded ciphertext + nonce."""
    if not isinstance(plaintext, str):
        raise TypeError("Plaintext must be a string")

    nonce = os.urandom(12)  # GCM recommended nonce size
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None) # No associated data

    # Prepend nonce to ciphertext and encode together
    encrypted_package = base64.urlsafe_b64encode(nonce + ciphertext)
    return encrypted_package.decode('utf-8')

def decrypt_data(key: bytes, encrypted_package_b64: str) -> str:
    """Decrypts base64-encoded ciphertext + nonce using AES-GCM."""
    try:
        encrypted_package = base64.urlsafe_b64decode(encrypted_package_b64.encode('utf-8'))
    except (TypeError, base64.binascii.Error) as e:
        # Log error appropriately in a real application
        print(f"Error base64 decoding: {e}")
        raise ValueError("Invalid encrypted data format") from e

    if len(encrypted_package) < 13: # Nonce (12) + at least 1 byte ciphertext
        raise ValueError("Invalid encrypted data length")

    nonce = encrypted_package[:12]
    ciphertext = encrypted_package[12:]
    aesgcm = AESGCM(key)

    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None) # No associated data
        return decrypted_bytes.decode('utf-8')
    except InvalidTag:
        # Log error appropriately
        print("Decryption failed: Invalid Tag (tampering or wrong key/nonce)")
        raise ValueError("Decryption failed - data may be corrupt or key is incorrect")
    except Exception as e:
        # Catch other potential issues during decryption
        print(f"An unexpected error occurred during decryption: {e}")
        raise ValueError("Decryption failed due to an unexpected error") from e 