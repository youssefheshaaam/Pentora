#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Pentora - Authentication module
# Copyright (C) 2025 Pentora Team

import os
import json
import re
import uuid
import hashlib
import hmac
import base64
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

# Constants for validation
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
PASSWORD_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$")
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,30}$")

# Constants for security
SALT_BYTES = 32
HASH_ITERATIONS = 100000
HASH_ALGORITHM = 'sha256'
KEY_LENGTH = 32

class AuthError(Exception):
    """Authentication related errors"""
    pass

class ValidationError(Exception):
    """Validation related errors"""
    pass

class UserManager:
    """Manages user accounts, authentication, and session management"""
    
    def __init__(self, data_path: Optional[str] = None):
        """Initialize the user manager
        
        Args:
            data_path: Path to store user data. If None, uses the default location.
        """
        if data_path is None:
            # Create directory in user's home directory
            home_dir = Path.home()
            self.data_dir = home_dir / ".pentora"
            self.data_dir.mkdir(exist_ok=True)
            self.data_file = self.data_dir / "users.json"
            self.credentials_file = self.data_dir / "remembered_credentials.json"
        else:
            self.data_dir = Path(data_path)
            self.data_dir.mkdir(exist_ok=True)
            self.data_file = self.data_dir / "users.json"
            self.credentials_file = self.data_dir / "remembered_credentials.json"
        
        # Initialize or load user database
        self.users = self.load_users()
        
        # Track current user
        self.current_user = None
        
        # Dictionary to store password reset codes
        self.reset_codes = {}
        
    def load_users(self) -> Dict:
        """Load user data from file
        
        Returns:
            Dict containing user data
        """
        if not self.data_file.exists():
            # Create empty user database
            empty_db = {"users": {}}
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump(empty_db, f, indent=2)
            return empty_db
        
        try:
            with open(self.data_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            # If file is corrupted, create a new one
            logging.error(f"User database file corrupted, creating new one")
            empty_db = {"users": {}}
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump(empty_db, f, indent=2)
            return empty_db
    
    def save_users(self) -> None:
        """Save user data to file"""
        try:
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump(self.users, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save user database: {e}")
            raise AuthError(f"Failed to save user database: {e}")
    
    def hash_password(self, password: str) -> Tuple[str, str]:
        """Hash a password with a random salt
        
        Args:
            password: Plain text password to hash
            
        Returns:
            Tuple of (salt_base64, hash_base64)
        """
        salt = os.urandom(SALT_BYTES)
        hash_bytes = hashlib.pbkdf2_hmac(
            HASH_ALGORITHM, 
            password.encode('utf-8'), 
            salt, 
            HASH_ITERATIONS, 
            dklen=KEY_LENGTH
        )
        
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        hash_b64 = base64.b64encode(hash_bytes).decode('utf-8')
        
        return salt_b64, hash_b64
    
    def verify_password(self, password: str, salt_b64: str, stored_hash_b64: str) -> bool:
        """Verify a password against a stored hash
        
        Args:
            password: Plain text password to verify
            salt_b64: Base64 encoded salt
            stored_hash_b64: Base64 encoded hash to compare against
            
        Returns:
            True if the password matches, False otherwise
        """
        salt = base64.b64decode(salt_b64)
        hash_bytes = hashlib.pbkdf2_hmac(
            HASH_ALGORITHM, 
            password.encode('utf-8'), 
            salt, 
            HASH_ITERATIONS, 
            dklen=KEY_LENGTH
        )
        
        calculated_hash_b64 = base64.b64encode(hash_bytes).decode('utf-8')
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(calculated_hash_b64, stored_hash_b64)
    
    def validate_email(self, email: str) -> bool:
        """Validate email format
        
        Args:
            email: Email to validate
            
        Returns:
            True if valid, False otherwise
        """
        return bool(EMAIL_REGEX.match(email))
    
    def validate_username(self, username: str) -> bool:
        """Validate username format
        
        Args:
            username: Username to validate
            
        Returns:
            True if valid, False otherwise
        """
        return bool(USERNAME_REGEX.match(username))
    
    def validate_password(self, password: str) -> Dict[str, bool]:
        """Validate password strength
        
        Args:
            password: Password to validate
            
        Returns:
            Dictionary with validation results for each criterion
        """
        validation = {
            "length": len(password) >= 8,
            "uppercase": any(c.isupper() for c in password),
            "lowercase": any(c.islower() for c in password),
            "number": any(c.isdigit() for c in password),
            "valid": bool(PASSWORD_REGEX.match(password))
        }
        return validation
    
    def is_username_taken(self, username: str) -> bool:
        """Check if a username is already taken
        
        Args:
            username: Username to check
            
        Returns:
            True if taken, False otherwise
        """
        for user_id, user_data in self.users.get("users", {}).items():
            if user_data.get("username", "").lower() == username.lower():
                return True
        return False
    
    def is_email_taken(self, email: str) -> bool:
        """Check if an email is already taken
        
        Args:
            email: Email to check
            
        Returns:
            True if taken, False otherwise
        """
        for user_id, user_data in self.users.get("users", {}).items():
            if user_data.get("email", "").lower() == email.lower():
                return True
        return False
    
    def register_user(self, username: str, email: str, password: str) -> str:
        """Register a new user
        
        Args:
            username: Username
            email: Email address
            password: Password
            
        Returns:
            User ID of the newly registered user
            
        Raises:
            ValidationError: If any validation fails
            AuthError: If the user already exists
        """
        # Validate inputs
        if not self.validate_username(username):
            raise ValidationError("Username must be 3-30 characters and can only contain letters, numbers, underscores, and hyphens")
        
        if not self.validate_email(email):
            raise ValidationError("Invalid email format")
        
        password_validation = self.validate_password(password)
        if not password_validation["valid"]:
            raise ValidationError("Password must be at least 8 characters and contain uppercase and lowercase letters and numbers")
        
        if self.is_username_taken(username):
            raise AuthError("Username already taken")
        
        if self.is_email_taken(email):
            raise AuthError("Email already taken")
        
        # Create user
        user_id = str(uuid.uuid4())
        salt, hash_value = self.hash_password(password)
        
        if "users" not in self.users:
            self.users["users"] = {}
        
        self.users["users"][user_id] = {
            "username": username,
            "email": email.lower(),
            "salt": salt,
            "hash": hash_value,
            "created_at": time.time(),
            "last_login": None
        }
        
        self.save_users()
        return user_id
    
    def login(self, username_or_email: str, password: str) -> Tuple[bool, str, str]:
        """Authenticate a user
        
        Args:
            username_or_email: Username or email to log in with
            password: Password to verify
            
        Returns:
            Tuple of (success, user_id, username)
            
        Raises:
            AuthError: If authentication fails
        """
        username_or_email = username_or_email.lower()
        
        # Find the user by username or email
        user_id = None
        user_data = None
        
        for uid, data in self.users.get("users", {}).items():
            if (data.get("username", "").lower() == username_or_email or 
                data.get("email", "").lower() == username_or_email):
                user_id = uid
                user_data = data
                break
        
        if not user_id or not user_data:
            return False, "", ""
        
        # Verify password
        if not self.verify_password(password, user_data["salt"], user_data["hash"]):
            return False, "", ""
        
        # Update last login time
        self.users["users"][user_id]["last_login"] = time.time()
        self.save_users()
        
        # Set current user
        self.current_user = {
            "user_id": user_id,
            "username": user_data["username"],
            "email": user_data["email"]
        }
        
        return True, user_id, user_data["username"]
    
    def logout(self) -> None:
        """Log out the current user"""
        self.current_user = None
        self.clear_remembered_credentials()
    
    def get_current_user(self) -> Optional[Dict]:
        """Get the current logged in user
        
        Returns:
            Dict with user details or None if no user is logged in
        """
        return self.current_user
    
    def is_logged_in(self) -> bool:
        """Check if a user is currently logged in
        
        Returns:
            True if a user is logged in, False otherwise
        """
        return self.current_user is not None
    
    def generate_reset_code(self, email: str) -> Tuple[bool, str]:
        """Generate a password reset code for a user
        
        Args:
            email: Email address of the user
            
        Returns:
            Tuple of (success, reset_code)
            
        Raises:
            AuthError: If the email doesn't exist
        """
        email = email.lower()
        
        # Find the user by email
        user_id = None
        
        for uid, data in self.users.get("users", {}).items():
            if data.get("email", "").lower() == email:
                user_id = uid
                break
        
        if not user_id:
            return False, ""
        
        # Generate a reset code
        reset_code = str(uuid.uuid4())[:8].upper()
        
        # Store the reset code with an expiration time (30 minutes)
        self.reset_codes[reset_code] = {
            "user_id": user_id,
            "expires_at": time.time() + 30 * 60
        }
        
        return True, reset_code
    
    def verify_reset_code(self, reset_code: str) -> Tuple[bool, str]:
        """Verify a password reset code
        
        Args:
            reset_code: Reset code to verify
            
        Returns:
            Tuple of (success, user_id)
        """
        if reset_code not in self.reset_codes:
            return False, ""
        
        reset_data = self.reset_codes[reset_code]
        
        # Check if the code has expired
        if reset_data["expires_at"] < time.time():
            del self.reset_codes[reset_code]
            return False, ""
        
        return True, reset_data["user_id"]
    
    def reset_password(self, reset_code: str, new_password: str) -> bool:
        """Reset a user's password using a reset code
        
        Args:
            reset_code: Reset code
            new_password: New password
            
        Returns:
            True if successful, False otherwise
            
        Raises:
            ValidationError: If the password is invalid
            AuthError: If the reset code is invalid
        """
        # Validate the password
        password_validation = self.validate_password(new_password)
        if not password_validation["valid"]:
            raise ValidationError("Password must be at least 8 characters and contain uppercase and lowercase letters and numbers")
        
        # Verify the reset code
        valid, user_id = self.verify_reset_code(reset_code)
        if not valid:
            raise AuthError("Invalid or expired reset code")
        
        # Update the password
        salt, hash_value = self.hash_password(new_password)
        self.users["users"][user_id]["salt"] = salt
        self.users["users"][user_id]["hash"] = hash_value
        
        # Remove the reset code
        del self.reset_codes[reset_code]
        
        self.save_users()
        return True
    
    def save_remembered_credentials(self, username_or_email: str) -> None:
        """Save the credentials for 'Remember me' functionality
        
        Args:
            username_or_email: Username or email to remember
        """
        if not self.current_user:
            return
            
        data = {
            "username_or_email": username_or_email,
            "user_id": self.current_user["user_id"]
        }
        
        try:
            with open(self.credentials_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save remembered credentials: {e}")
    
    def load_remembered_credentials(self) -> Tuple[bool, str]:
        """Load remembered credentials
        
        Returns:
            Tuple of (success, username_or_email)
        """
        if not self.credentials_file.exists():
            return False, ""
            
        try:
            with open(self.credentials_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            username_or_email = data.get("username_or_email", "")
            if username_or_email:
                return True, username_or_email
                
        except Exception as e:
            logging.error(f"Failed to load remembered credentials: {e}")
            
        return False, ""
    
    def clear_remembered_credentials(self) -> None:
        """Clear remembered credentials"""
        if self.credentials_file.exists():
            try:
                os.unlink(self.credentials_file)
            except Exception as e:
                logging.error(f"Failed to clear remembered credentials: {e}") 