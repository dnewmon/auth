import os
import secrets
import string
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
    key = kdf.derive(password.encode("utf-8"))
    return key


def encrypt_data(key: bytes, plaintext: str) -> str:
    """Encrypts plaintext using AES-GCM and returns base64-encoded ciphertext + nonce."""
    if not isinstance(plaintext, str):
        raise TypeError("Plaintext must be a string")

    nonce = os.urandom(12)  # GCM recommended nonce size
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)  # No associated data

    # Prepend nonce to ciphertext and encode together
    encrypted_package = base64.urlsafe_b64encode(nonce + ciphertext)
    return encrypted_package.decode("utf-8")


def decrypt_data(key: bytes, encrypted_package_b64: str) -> str:
    """Decrypts base64-encoded ciphertext + nonce using AES-GCM."""
    try:
        encrypted_package = base64.urlsafe_b64decode(encrypted_package_b64.encode("utf-8"))
    except (TypeError, base64.binascii.Error) as e:
        # Log error appropriately in a real application
        print(f"Error base64 decoding: {e}")
        raise ValueError("Invalid encrypted data format") from e

    if len(encrypted_package) < 13:  # Nonce (12) + at least 1 byte ciphertext
        raise ValueError("Invalid encrypted data length")

    nonce = encrypted_package[:12]
    ciphertext = encrypted_package[12:]
    aesgcm = AESGCM(key)

    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)  # No associated data
        return decrypted_bytes.decode("utf-8")
    except InvalidTag:
        # Log error appropriately
        print("Decryption failed: Invalid Tag (tampering or wrong key/nonce)")
        raise ValueError("Decryption failed - data may be corrupt or key is incorrect")
    except Exception as e:
        # Catch other potential issues during decryption
        print(f"An unexpected error occurred during decryption: {e}")
        raise ValueError("Decryption failed due to an unexpected error") from e


# Additional functions for two-tier encryption with recovery keys


def generate_master_encryption_key() -> bytes:
    """Generate a random 256-bit Master Encryption Key (MEK)."""
    return os.urandom(32)  # 32 bytes = 256 bits


def encrypt_master_key(master_key: bytes, password: str, salt: bytes) -> str:
    """Encrypt the MEK using a Key Encryption Key (KEK) derived from password."""
    key_encryption_key = derive_key(password, salt)
    encrypted_master_key = encrypt_data(key_encryption_key, base64.urlsafe_b64encode(master_key).decode("utf-8"))
    return encrypted_master_key


def decrypt_master_key(encrypted_master_key: str, password: str, salt: bytes) -> bytes:
    """Decrypt the MEK using a Key Encryption Key (KEK) derived from password."""
    key_encryption_key = derive_key(password, salt)
    decrypted_master_key_b64 = decrypt_data(key_encryption_key, encrypted_master_key)
    return base64.urlsafe_b64decode(decrypted_master_key_b64.encode("utf-8"))


def generate_recovery_key(length=16) -> str:
    """Generate a random recovery key of specified length."""
    # Use uppercase letters and digits, excluding similar looking characters
    alphabet = "".join(set(string.ascii_uppercase + string.digits) - set("O01IL"))
    # Generate random string
    raw_key = "".join(secrets.choice(alphabet) for _ in range(length))
    # Format as XXXX-XXXX-XXXX-XXXX
    if length == 16:
        return f"{raw_key[:4]}-{raw_key[4:8]}-{raw_key[8:12]}-{raw_key[12:16]}"
    return raw_key


def generate_recovery_keys(count=5) -> list:
    """Generate a specified number of recovery keys."""
    return [generate_recovery_key() for _ in range(count)]


def hash_recovery_key(recovery_key: str) -> str:
    """Hash a recovery key to safely store its identifier."""
    # Remove formatting characters
    clean_key = recovery_key.replace("-", "")
    # Create a hash for safe storage
    digest = hashes.Hash(hashes.SHA256())
    digest.update(clean_key.encode("utf-8"))
    return base64.urlsafe_b64encode(digest.finalize()).decode("utf-8")


def encrypt_master_key_with_recovery_key(master_key: bytes, recovery_key: str) -> tuple:
    """
    Encrypt the MEK with a recovery key.
    Returns (salt, encrypted_key, key_hash)
    """
    # Remove formatting characters
    clean_key = recovery_key.replace("-", "")

    # Generate a unique salt for this recovery key
    salt = os.urandom(16)

    # Derive encryption key from recovery key
    recovery_encryption_key = derive_key(clean_key, salt)

    # Encrypt the master key
    master_key_b64 = base64.urlsafe_b64encode(master_key).decode("utf-8")
    encrypted_master_key = encrypt_data(recovery_encryption_key, master_key_b64)

    # Hash the recovery key for storage (to verify the correct key was provided)
    key_hash = hash_recovery_key(recovery_key)

    return (salt, encrypted_master_key, key_hash)


def decrypt_master_key_with_recovery_key(encrypted_master_key: str, recovery_key: str, salt: bytes) -> bytes:
    """
    Decrypt the MEK using a recovery key.
    """
    # Remove formatting characters
    clean_key = recovery_key.replace("-", "")

    # Derive decryption key from recovery key
    recovery_decryption_key = derive_key(clean_key, salt)

    # Decrypt the master key
    try:
        decrypted_master_key_b64 = decrypt_data(recovery_decryption_key, encrypted_master_key)
        return base64.urlsafe_b64decode(decrypted_master_key_b64.encode("utf-8"))
    except ValueError:
        raise ValueError("Invalid recovery key or corrupted data")
