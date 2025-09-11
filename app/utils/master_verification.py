import time
import secrets
import base64
from flask import session
from flask_login import current_user
from typing import Optional, Dict, Any
from .encryption import encrypt_data, decrypt_data, derive_key


class MasterVerificationManager:
    """Manages master password verification status and timing."""
    
    SESSION_KEY = "master_password_verified"
    SESSION_TOKEN_KEY = "session_token"
    ENCRYPTED_MASTER_KEY = "encrypted_master_key"
    TIMEOUT_SECONDS = 300  # 5 minutes
    
    @classmethod
    def verify_and_store(cls, master_password: str) -> str:
        """
        Verify master password and store verification in session with session token.
        
        Args:
            master_password: The master password to verify
            
        Returns:
            Session token for accessing the encrypted master key
            
        Raises:
            ValueError: If master password is invalid
        """
        try:
            # Validate master password by attempting to get master key
            master_key = current_user.get_master_key(master_password)
            
            # Generate a secure session token
            session_token = secrets.token_urlsafe(32)
            
            # Encrypt the master key using the session token as the encryption key
            # Derive a key from the session token
            token_key = derive_key(session_token, current_user.encryption_salt)
            encrypted_master_key = encrypt_data(token_key, base64.urlsafe_b64encode(master_key).decode('utf-8'))
            
            # Store verification in session with timestamp
            session[cls.SESSION_KEY] = {
                "verified": True,
                "timestamp": int(time.time())
            }
            session[cls.SESSION_TOKEN_KEY] = session_token
            session[cls.ENCRYPTED_MASTER_KEY] = encrypted_master_key
            session.modified = True
            
            return session_token
        except ValueError:
            raise ValueError("Invalid master password")
    
    @classmethod
    def is_verified(cls) -> bool:
        """
        Check if master password verification is still valid.
        
        Returns:
            True if verification is valid and not expired, False otherwise
        """
        verification = session.get(cls.SESSION_KEY)
        if not verification or not verification.get("verified"):
            return False
        
        # Check if verification has expired
        current_time = int(time.time())
        if current_time - verification["timestamp"] > cls.TIMEOUT_SECONDS:
            cls.clear_verification()
            return False
        
        return True
    
    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        """
        Get current master verification status with timing information.
        
        Returns:
            Dictionary containing verification status, expiry time, and time remaining
        """
        verification = session.get(cls.SESSION_KEY)
        current_time = int(time.time())
        
        if not verification or not verification.get("verified"):
            return {
                "verified": False,
                "expires_at": None,
                "time_remaining": 0
            }
        
        verification_time = verification["timestamp"]
        expires_at = verification_time + cls.TIMEOUT_SECONDS
        time_remaining = max(0, expires_at - current_time)
        
        # If expired, clean up the session
        if time_remaining == 0:
            cls.clear_verification()
        
        return {
            "verified": time_remaining > 0,
            "expires_at": expires_at,
            "time_remaining": time_remaining
        }
    
    @classmethod
    def get_master_key_from_session(cls, session_token: str) -> bytes:
        """
        Get the master encryption key using the session token.
        
        Args:
            session_token: The session token for decrypting the master key
            
        Returns:
            The master encryption key
            
        Raises:
            ValueError: If session token is invalid or verification has expired
        """
        # Check if verification is still valid
        if not cls.is_verified():
            raise ValueError("Master password verification required or expired")
        
        # Check if session token matches the stored one
        stored_token = session.get(cls.SESSION_TOKEN_KEY)
        if not stored_token or stored_token != session_token:
            raise ValueError("Invalid session token")
        
        # Get the encrypted master key from session
        encrypted_master_key = session.get(cls.ENCRYPTED_MASTER_KEY)
        if not encrypted_master_key:
            raise ValueError("No encrypted master key found in session")
        
        try:
            # Decrypt the master key using the session token
            token_key = derive_key(session_token, current_user.encryption_salt)
            decrypted_master_key_b64 = decrypt_data(token_key, encrypted_master_key)
            return base64.urlsafe_b64decode(decrypted_master_key_b64.encode('utf-8'))
        except Exception as e:
            raise ValueError(f"Failed to decrypt master key: {str(e)}")

    @classmethod
    def clear_verification(cls) -> None:
        """Clear master password verification from session."""
        session.pop(cls.SESSION_KEY, None)
        session.pop(cls.SESSION_TOKEN_KEY, None)
        session.pop(cls.ENCRYPTED_MASTER_KEY, None)
        session.modified = True
    
    @classmethod
    def require_verification(cls) -> bool:
        """
        Decorator helper function to check if master verification is required.
        
        Returns:
            True if verification is valid, False if verification required
        """
        return cls.is_verified()
    
    @classmethod
    def refresh_verification(cls) -> None:
        """
        Refresh the verification timestamp if currently verified.
        This can be used to extend the session when user is actively using the app.
        """
        verification = session.get(cls.SESSION_KEY)
        if verification and verification.get("verified"):
            verification["timestamp"] = int(time.time())
            session[cls.SESSION_KEY] = verification
            session.modified = True