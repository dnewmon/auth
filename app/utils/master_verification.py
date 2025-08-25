import time
from flask import session
from flask_login import current_user
from typing import Optional, Dict, Any


class MasterVerificationManager:
    """Manages master password verification status and timing."""
    
    SESSION_KEY = "master_password_verified"
    TIMEOUT_SECONDS = 300  # 5 minutes
    
    @classmethod
    def verify_and_store(cls, master_password: str) -> bool:
        """
        Verify master password and store verification in session.
        
        Args:
            master_password: The master password to verify
            
        Returns:
            True if verification successful, False otherwise
            
        Raises:
            ValueError: If master password is invalid
        """
        try:
            # Validate master password by attempting to get master key
            current_user.get_master_key(master_password)
            
            # Store verification in session with timestamp
            session[cls.SESSION_KEY] = {
                "verified": True,
                "timestamp": int(time.time())
            }
            session.modified = True
            
            return True
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
    def clear_verification(cls) -> None:
        """Clear master password verification from session."""
        session.pop(cls.SESSION_KEY, None)
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