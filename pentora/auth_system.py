#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Pentora - Authentication System (Consolidated)
# Copyright (C) 2025 Pentora Team

import os
import sys
import json
import re
import uuid
import hashlib
import hmac
import base64
import time
import logging
# import requests # Not used in provided auth files, consider removing if not needed by PentoraMainWindow
# import tempfile # Not used

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QStackedWidget, QMessageBox, QPushButton, QFrame, QLineEdit, 
    QCheckBox, QProgressBar, QSpacerItem, QSizePolicy, 
    QGraphicsDropShadowEffect, QMenu, QFormLayout
)
from PyQt5.QtCore import (
    Qt, QSize, QPropertyAnimation, QEasingCurve, QPoint, QTimer, 
    pyqtSignal, QRegExp
)
from PyQt5.QtGui import (
    QPixmap, QIcon, QFont, QColor, QCursor, QPalette, QBrush, 
    QLinearGradient, QFontDatabase, QPainter, QRegExpValidator
)

# Attempt to import PentoraMainWindow and other necessary components from pentora_gui
# This path is relative to this file (pentora/auth_system.py)
try:
    from .pentora_gui import PentoraMainWindow, get_app_icon_path
except ImportError as e:
    logging.error(f"Could not import PentoraMainWindow or get_app_icon_path: {e}. Main application will not load after auth.")
    PentoraMainWindow = QWidget # Placeholder if import fails
    def get_app_icon_path(): return "" # Placeholder

# IMPORTANT: For the checkbox icon (check.png) to work, a Qt resource file (.qrc)
# must be created. Example: create 'pentora_resources.qrc' in the project root.
# Inside pentora_resources.qrc:
# <!DOCTYPE RCC><RCC version="1.0">
# <qresource>
#     <file alias="icons/check.png">pentora/resources/images/check.png</file>
# </qresource>
# </RCC>
# Then compile it: pyrcc5 pentora_resources.qrc -o pentora_resources_rc.py
# And import it here: from . import pentora_resources_rc # Assuming _rc.py is in 'pentora' dir
# Or: import pentora_resources_rc # If _rc.py is in project root and root is in PYTHONPATH
# import pentora_resources_rc # Importing from project root - User wants to avoid this direct import for now.

# Constants for validation (from auth.py)
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
PASSWORD_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$")
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,30}$")

# Constants for security (from auth.py)
SALT_BYTES = 32
HASH_ITERATIONS = 100000
HASH_ALGORITHM = 'sha256'
KEY_LENGTH = 32

# Modern color palette (from auth_ui.py)
COLORS = {
    "primary": "#6C63FF",
    "primary_hover": "#5A52D9",
    "primary_active": "#4A44B2",
    "secondary": "#07B89E",
    "secondary_hover": "#06A790",
    "secondary_light": "#B0F4E6",
    "danger": "#FF6B6B",
    "success": "#4ECB71",
    "warning": "#FFBE0B",
    "info": "#4FC3F7",
    "text_primary": "#E0E0E0",
    "text_secondary": "#9E9E9E",
    "text_light": "#FFFFFF",
    "text_muted": "#757575",
    "background": "#252525",
    "surface": "#303030",
    "border": "#424242",
    "border_focus": "#6C63FF",
    "divider": "#424242",
    "shadow": "#12121280",
}

# Enhanced base styles for common widgets (adapted for global application in PentoraAuthApp)
# Selectors like #auth_frame, .auth_input will be used by setting objectName or class property.
STYLE_SHEETS = {
    "container_frame": f"""
        QFrame#auth_frame {{
            background-color: {COLORS["surface"]};
            border-radius: 10px;
            border: 1px solid {COLORS["border"]};
        }}
    """,
    "title_label": f"""
        QLabel#auth_title {{
            color: {COLORS["primary"]};
            font-size: 22px;
            font-weight: bold;
            margin-bottom: 15px;
        }}
    """,
    "subtitle_label": f"""
        QLabel#auth_subtitle {{
            color: {COLORS["text_secondary"]};
            font-size: 14px;
            margin-bottom: 10px;
        }}
    """,
    "field_label": f"""
        QLabel.auth_field_label {{
            color: {COLORS["text_secondary"]};
            font-size: 12px;
            font-weight: 600;
            margin-bottom: 4px;
        }}
    """,
    "line_edit": f"""
        QLineEdit.auth_input {{
            background-color: {COLORS["surface"]};
            color: {COLORS["text_primary"]};
            border: 1px solid {COLORS["border"]};
            border-radius: 6px;
            padding: 10px 12px;
            font-size: 12px;
            min-height: 20px;
        }}
        QLineEdit.auth_input:focus {{
            border: 2px solid {COLORS["primary"]};
            background-color: {COLORS["surface"]};
        }}
        QLineEdit.auth_input:hover:!focus {{
            border: 1px solid #555555;
        }}
        QLineEdit.auth_input[echoMode="2"] {{
            lineedit-password-character: 9679;
        }}
        QLineEdit.auth_input:disabled {{
            background-color: {COLORS["background"]};
            color: {COLORS["text_muted"]};
        }}
    """,
    "primary_button": f"""
        QPushButton.auth_button_primary {{
            background-color: {COLORS["primary"]};
            color: {COLORS["text_light"]};
            font-weight: bold;
            border: none;
            border-radius: 6px;
            padding: 10px 16px;
            min-height: 20px;
            font-size: 13px;
        }}
        QPushButton.auth_button_primary:hover {{
            background-color: {COLORS["primary_hover"]};
        }}
        QPushButton.auth_button_primary:pressed {{
            background-color: {COLORS["primary_active"]};
        }}
        QPushButton.auth_button_primary:disabled {{
            background-color: {COLORS["text_muted"]}; /* Darker disabled for dark theme */
            color: {COLORS["background"]};
        }}
    """,
    "secondary_button": f"""
        QPushButton.auth_button_secondary {{
            background-color: {COLORS["surface"]};
            color: {COLORS["primary"]};
            border: 1px solid {COLORS["primary"]};
            border-radius: 6px;
            padding: 10px 16px;
            min-height: 20px;
            font-size: 13px;
        }}
        QPushButton.auth_button_secondary:hover {{
            background-color: {COLORS["primary"] + "1A"}; /* Alpha for hover */
        }}
        QPushButton.auth_button_secondary:pressed {{
            background-color: {COLORS["primary"] + "33"}; /* Alpha for pressed */
        }}
    """,
    "text_button": f"""
        QPushButton.auth_button_text {{
            background-color: transparent;
            color: {COLORS["primary"]};
            border: none;
            text-decoration: none; /* Usually handled by not having a border */
            padding: 5px;
            font-size: 12px;
        }}
        QPushButton.auth_button_text:hover {{
            color: {COLORS["primary_hover"]};
            text-decoration: underline;
        }}
        QPushButton.auth_button_text:pressed {{
            color: {COLORS["primary_active"]};
        }}
    """,
    "checkbox": f"""
        QCheckBox.auth_checkbox {{
            color: {COLORS["text_secondary"]};
            font-size: 12px;
            spacing: 8px;
        }}
        QCheckBox.auth_checkbox::indicator {{
            width: 18px;
            height: 18px;
            border-radius: 4px;
            border: 1px solid {COLORS["border"]};
            background-color: {COLORS["background"]};
        }}
        QCheckBox.auth_checkbox::indicator:unchecked:hover {{
            border: 1px solid {COLORS["primary"]};
        }}
        QCheckBox.auth_checkbox::indicator:checked {{
            background-color: {COLORS["primary"]};
            border: 1px solid {COLORS["primary"]};
            image: url(:/icons/check.png); /* Using image as requested */
        }}
        QCheckBox.auth_checkbox::indicator:checked:hover {{
            border: 1px solid {COLORS["primary_hover"]};
            background-color: {COLORS["primary_hover"]};
        }}
    """
}

# Function to apply a drop shadow (from auth_ui.py)
def apply_shadow(widget, radius=15, x_offset=0, y_offset=3, color_str=COLORS["shadow"]):
    shadow = QGraphicsDropShadowEffect(widget)
    shadow.setBlurRadius(radius)
    shadow.setColor(QColor(color_str))
    shadow.setOffset(x_offset, y_offset)
    widget.setGraphicsEffect(shadow)

# Custom Exceptions (from auth.py)
class AuthError(Exception):
    """Authentication related errors"""
    pass

class ValidationError(Exception):
    """Validation related errors"""
    pass

# UserManager class (from auth.py)
class UserManager:
    def __init__(self, data_path: Optional[str] = None):
        if data_path is None:
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
        
        self.users = self.load_users()
        self.current_user = None
        self.reset_codes = {}
    
    def load_users(self) -> Dict:
        if not self.data_file.exists():
            empty_db = {"users": {}}
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump(empty_db, f, indent=2)
            return empty_db
        
        try:
            with open(self.data_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logging.error(f"User database file corrupted, creating new one")
            empty_db = {"users": {}}
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump(empty_db, f, indent=2)
            return empty_db
    
    def save_users(self) -> None:
        try:
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump(self.users, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save user database: {e}")
            raise AuthError(f"Failed to save user database: {e}")
    
    def hash_password(self, password: str) -> Tuple[str, str]:
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
        salt = base64.b64decode(salt_b64)
        hash_bytes = hashlib.pbkdf2_hmac(
            HASH_ALGORITHM, 
            password.encode('utf-8'), 
            salt, 
            HASH_ITERATIONS, 
            dklen=KEY_LENGTH
        )
        calculated_hash_b64 = base64.b64encode(hash_bytes).decode('utf-8')
        return hmac.compare_digest(calculated_hash_b64, stored_hash_b64)
    
    def validate_email(self, email: str) -> bool:
        return bool(EMAIL_REGEX.match(email))
    
    def validate_username(self, username: str) -> bool:
        return bool(USERNAME_REGEX.match(username))
    
    def validate_password(self, password: str) -> Dict[str, bool]:
        validation = {
            "length": len(password) >= 8,
            "uppercase": any(c.isupper() for c in password),
            "lowercase": any(c.islower() for c in password),
            "number": any(c.isdigit() for c in password),
            "valid": bool(PASSWORD_REGEX.match(password))
        }
        return validation
    
    def is_username_taken(self, username: str) -> bool:
        for user_id, user_data in self.users.get("users", {}).items():
            if user_data.get("username", "").lower() == username.lower():
                return True
        return False
    
    def is_email_taken(self, email: str) -> bool:
        for user_id, user_data in self.users.get("users", {}).items():
            if user_data.get("email", "").lower() == email.lower():
                return True
        return False
    
    def register_user(self, username: str, email: str, password: str) -> str:
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
        username_or_email = username_or_email.lower()
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
        if not self.verify_password(password, user_data["salt"], user_data["hash"]):
            return False, "", ""
        
        self.users["users"][user_id]["last_login"] = time.time()
        self.save_users()
        self.current_user = {"user_id": user_id, "username": user_data["username"], "email": user_data["email"]}
        return True, user_id, user_data["username"]
    
    def logout(self) -> None:
        self.current_user = None
        self.clear_remembered_credentials()
    
    def get_current_user(self) -> Optional[Dict]:
        return self.current_user
    
    def is_logged_in(self) -> bool:
        return self.current_user is not None
    
    def generate_reset_code(self, email: str) -> Tuple[bool, str]:
        email = email.lower()
        user_id = None
        for uid, data in self.users.get("users", {}).items():
            if data.get("email", "").lower() == email:
                user_id = uid
                break
        if not user_id:
            return False, ""
        reset_code = str(uuid.uuid4())[:8].upper()
        self.reset_codes[reset_code] = {"user_id": user_id, "expires_at": time.time() + 30 * 60}
        return True, reset_code
    
    def verify_reset_code(self, reset_code: str) -> Tuple[bool, str]:
        if reset_code not in self.reset_codes:
            return False, ""
        reset_data = self.reset_codes[reset_code]
        if reset_data["expires_at"] < time.time():
            del self.reset_codes[reset_code]
            return False, ""
        return True, reset_data["user_id"]
    
    def reset_password(self, reset_code: str, new_password: str) -> bool:
        password_validation = self.validate_password(new_password)
        if not password_validation["valid"]:
            raise ValidationError("Password must be at least 8 characters and contain uppercase and lowercase letters and numbers")
        valid, user_id = self.verify_reset_code(reset_code)
        if not valid:
            raise AuthError("Invalid or expired reset code")
        salt, hash_value = self.hash_password(new_password)
        self.users["users"][user_id]["salt"] = salt
        self.users["users"][user_id]["hash"] = hash_value
        del self.reset_codes[reset_code]
        self.save_users()
        return True
    
    def save_remembered_credentials(self, username_or_email: str) -> None:
        if not self.current_user: return
        data = {"username_or_email": username_or_email, "user_id": self.current_user["user_id"]}
        try:
            with open(self.credentials_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save remembered credentials: {e}")
    
    def load_remembered_credentials(self) -> Tuple[bool, str]:
        if not self.credentials_file.exists(): return False, ""
        try:
            with open(self.credentials_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            username_or_email = data.get("username_or_email", "")
            if username_or_email: return True, username_or_email
        except Exception as e:
            logging.error(f"Failed to load remembered credentials: {e}")
        return False, ""
    
    def clear_remembered_credentials(self) -> None:
        if self.credentials_file.exists():
            try:
                os.unlink(self.credentials_file)
            except Exception as e:
                logging.error(f"Failed to clear remembered credentials: {e}")

# UI Helper Classes (from auth_ui.py)
class FormStatusLabel(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setFixedHeight(16)
        self.clear()
    
    def clear(self):
        self.setText("")
        self.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; padding: 0px;")
        self.setVisible(False)
    
    def set_error(self, message):
        self.setText(f"❌ {message}")
        self.setStyleSheet(f"color: {COLORS['danger']}; font-size: 11px; padding: 0px;")
        self.setVisible(True)
    
    def set_success(self, message):
        self.setText(f"✓ {message}")
        self.setStyleSheet(f"color: {COLORS['success']}; font-size: 11px; padding: 0px;")
        self.setVisible(True)
    
    def set_info(self, message):
        self.setText(f"ℹ️ {message}")
        self.setStyleSheet(f"color: {COLORS['info']}; font-size: 11px; padding: 0px;")
        self.setVisible(True)

class PasswordStrengthWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        
        self.strength_bar = QProgressBar()
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(0)
        self.strength_bar.setFixedHeight(6)
        self.strength_bar.setStyleSheet(f"""
            QProgressBar {{ background-color: {COLORS["divider"]}; border: none; border-radius: 3px; }}
            QProgressBar::chunk {{ background-color: {COLORS["primary"]}; border-radius: 3px; }}
        """)
        layout.addWidget(self.strength_bar)
        
        requirements_layout = QHBoxLayout()
        requirements_layout.setContentsMargins(0, 5, 0, 0)
        requirements_layout.setSpacing(8)
        
        self.req_length = self._create_requirement_label("8+ chars")
        self.req_uppercase = self._create_requirement_label("A-Z")
        self.req_lowercase = self._create_requirement_label("a-z")
        self.req_number = self._create_requirement_label("0-9")
        
        requirements_layout.addWidget(self.req_length)
        requirements_layout.addWidget(self.req_uppercase)
        requirements_layout.addWidget(self.req_lowercase)
        requirements_layout.addWidget(self.req_number)
        requirements_layout.addStretch()
        layout.addLayout(requirements_layout)
    
    def _create_requirement_label(self, text):
        label = QLabel(f"❌ {text}")
        label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 10px;")
        return label
    
    def update_strength(self, password):
        if not password:
            self.strength_bar.setValue(0)
            self._update_requirement(self.req_length, False)
            self._update_requirement(self.req_uppercase, False)
            self._update_requirement(self.req_lowercase, False)
            self._update_requirement(self.req_number, False)
            self.strength_bar.setStyleSheet(f"""
                QProgressBar {{ background-color: {COLORS["divider"]}; border: none; border-radius: 3px; }}
                QProgressBar::chunk {{ background-color: {COLORS["text_muted"]}; border-radius: 3px; }}
            """)
            return
        
        length_ok = len(password) >= 8
        uppercase_ok = any(c.isupper() for c in password)
        lowercase_ok = any(c.islower() for c in password)
        number_ok = any(c.isdigit() for c in password)
        
        self._update_requirement(self.req_length, length_ok)
        self._update_requirement(self.req_uppercase, uppercase_ok)
        self._update_requirement(self.req_lowercase, lowercase_ok)
        self._update_requirement(self.req_number, number_ok)
        
        strength = sum([length_ok, uppercase_ok, lowercase_ok, number_ok]) * 25
        
        if strength < 50: color = COLORS["danger"]
        elif strength < 75: color = COLORS["warning"]
        elif strength < 100: color = COLORS["secondary"]
        else: color = COLORS["success"]
            
        self.strength_bar.setStyleSheet(f"""
            QProgressBar {{ background-color: {COLORS["divider"]}; border: none; border-radius: 3px; }}
            QProgressBar::chunk {{ background-color: {color}; border-radius: 3px; }}
        """)
        self.strength_bar.setValue(0) # For animation effect
        QTimer.singleShot(50, lambda: self.strength_bar.setValue(strength))
    
    def _update_requirement(self, label, is_met):
        if is_met:
            label.setText(label.text().replace("❌", "✓"))
            label.setStyleSheet(f"color: {COLORS['success']}; font-size: 11px;")
        else:
            label.setText(label.text().replace("✓", "❌"))
            label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px;")

# LoginWidget (Adapted from auth_ui.py)
class LoginWidget(QWidget):
    login_successful = pyqtSignal(str, str)
    show_register = pyqtSignal()
    show_forgot_password = pyqtSignal()
    
    def __init__(self, user_manager, parent=None):
        super().__init__(parent)
        self.user_manager = user_manager
        self.setup_fonts()
        self.init_ui()
        self.load_remembered_credentials()
    
    def setup_fonts(self):
        self.title_font = QFont("SF Pro Display", 18, QFont.Bold)
        self.subtitle_font = QFont("SF Pro Text", 10)
        self.button_font = QFont("SF Pro Text", 10, QFont.Bold)

        # Load Material Icons font
        # Path relative to this file (pentora/auth_system.py) -> pentora/resources/fonts/
        font_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources", "fonts", "MaterialIcons-Regular.ttf")
        font_id = QFontDatabase.addApplicationFont(font_path)
        if font_id != -1:
            font_families = QFontDatabase.applicationFontFamilies(font_id)
            if font_families:
                self.material_icons_font = QFont(font_families[0], 16) # Adjusted size
            else:
                logging.warning("Material Icons font loaded but no families found. Using fallback.")
                self.material_icons_font = QFont("Arial", 16) # Fallback
        else:
            logging.warning(f"Failed to load Material Icons font from: {font_path}. Using fallback.")
            self.material_icons_font = QFont("Arial", 16) # Fallback
    
    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.setSpacing(20)
        main_layout.setAlignment(Qt.AlignCenter) # Center content vertically

        # Title
        title_label = QLabel("Welcome!") # Changed text
        title_label.setFont(self.title_font)
        title_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 22px; font-weight: bold; margin-bottom: 5px;") # Adjusted style
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)
        
        # Logo (Pentora Logo Image) - Moved under title
        logo_pixmap = QPixmap(os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources", "images", "pentora_logo.png"))
        logo_label = QLabel()
        if not logo_pixmap.isNull():
            logo_label.setPixmap(logo_pixmap.scaled(150, 150, Qt.KeepAspectRatio, Qt.SmoothTransformation)) # Adjust size as needed
            logo_label.setStyleSheet("margin-bottom: 10px;")
        else:
            # Fallback text if image loading fails
            logo_label.setText("PENTORA") 
            logo_label.setStyleSheet(f"font-size: 36px; color: {COLORS['primary']}; font-weight: bold; margin-bottom: 10px;")
        logo_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(logo_label)
        
        subtitle_label = QLabel("Sign in to continue")
        subtitle_label.setFont(self.subtitle_font)
        subtitle_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 14px; margin-bottom: 20px;") # Adjusted style
        subtitle_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(subtitle_label)
        
        self.form_frame = QFrame() # Made it an instance member
        self.form_frame.setObjectName("auth_frame") # For global styling
        self.form_frame.setMaximumWidth(400) # Constrain width
        apply_shadow(self.form_frame)
        
        form_layout = QVBoxLayout(self.form_frame)
        form_layout.setContentsMargins(25, 25, 25, 25)
        form_layout.setSpacing(15)

        # Username
        username_label = QLabel("Username or Email")
        username_label.setProperty("class", "auth_field_label")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username or email")
        self.username_input.setProperty("class", "auth_input")
        self.username_status = FormStatusLabel()
        form_layout.addWidget(username_label)
        form_layout.addWidget(self.username_input)
        form_layout.addWidget(self.username_status)

        # Password
        password_label = QLabel("Password")
        password_label.setProperty("class", "auth_field_label")
        
        password_input_layout = QHBoxLayout()
        password_input_layout.setSpacing(0)
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setProperty("class", "auth_input")
        password_input_layout.addWidget(self.password_input)
        
        self.visibility_button = QPushButton()
        self.visibility_button.setCursor(Qt.PointingHandCursor)
        self.visibility_button.setFlat(True)
        self.visibility_button.setFixedSize(30,30)
        self.visibility_button.setIconSize(QSize(20,20))
        self.update_visibility_icon()
        self.visibility_button.clicked.connect(self.toggle_password_visibility)
        password_input_layout.addWidget(self.visibility_button)
        
        self.password_status = FormStatusLabel()
        form_layout.addWidget(password_label)
        form_layout.addLayout(password_input_layout)
        form_layout.addWidget(self.password_status)

        self.form_status = FormStatusLabel() # General form errors
        self.form_status.setAlignment(Qt.AlignCenter)
        form_layout.addWidget(self.form_status)
        
        # Remember me & Forgot Password
        remember_layout = QHBoxLayout()
        self.remember_checkbox = QCheckBox("Remember me")
        self.remember_checkbox.setProperty("class", "auth_checkbox")
        self.remember_checkbox.setCursor(Qt.PointingHandCursor)
        forgot_button = QPushButton("Forgot Password?")
        forgot_button.setProperty("class", "auth_button_text")
        forgot_button.setCursor(Qt.PointingHandCursor)
        forgot_button.clicked.connect(self.on_forgot_password)
        remember_layout.addWidget(self.remember_checkbox)
        remember_layout.addStretch()
        remember_layout.addWidget(forgot_button)
        form_layout.addLayout(remember_layout)
        
        self.login_button = QPushButton("Sign In")
        self.login_button.setFont(self.button_font)
        self.login_button.setProperty("class", "auth_button_primary")
        self.login_button.setMinimumHeight(40) # Adjusted height
        self.login_button.setCursor(Qt.PointingHandCursor)
        apply_shadow(self.login_button, 10, 0, 2)
        form_layout.addWidget(self.login_button)
        
        main_layout.addWidget(self.form_frame, 0, Qt.AlignCenter) # Center the frame

        # Register link
        register_layout = QHBoxLayout()
        register_layout.setContentsMargins(0, 15, 0, 0)
        register_label = QLabel("Don't have an account?")
        register_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        register_button = QPushButton("Sign Up")
        register_button.setProperty("class", "auth_button_text")
        register_button.setCursor(Qt.PointingHandCursor)
        register_button.clicked.connect(self.on_register)
        register_layout.addStretch()
        register_layout.addWidget(register_label)
        register_layout.addWidget(register_button)
        register_layout.addStretch()
        main_layout.addLayout(register_layout)
        main_layout.addStretch() # Pushes content to center if not enough

        # Connections
        self.username_input.textChanged.connect(self.on_username_changed)
        self.password_input.textChanged.connect(self.on_password_changed)
        self.login_button.clicked.connect(self.on_login)
        self.remember_checkbox.stateChanged.connect(self.on_remember_me_changed)
        self.username_input.returnPressed.connect(self.password_input.setFocus)
        self.password_input.returnPressed.connect(self.on_login)

        self.setTabOrder(self.username_input, self.password_input)
        self.setTabOrder(self.password_input, self.remember_checkbox)
        self.setTabOrder(self.remember_checkbox, self.login_button)
    
    def update_visibility_icon(self):
        if self.password_input.echoMode() == QLineEdit.Password:
            icon_text = "visibility_off" # Material icon name
        else:
            icon_text = "visibility"
        self.visibility_button.setFont(self.material_icons_font)
        self.visibility_button.setText(icon_text)
        # Adjust style if needed, e.g., color
        self.visibility_button.setStyleSheet(f"color: {COLORS['text_secondary']}; border: none; padding-right: 5px;")


    def toggle_password_visibility(self):
        if self.password_input.echoMode() == QLineEdit.Password:
            self.password_input.setEchoMode(QLineEdit.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
        self.update_visibility_icon()

    def on_username_changed(self, text):
        self.username_status.clear()
        self.form_status.clear()
    
    def on_password_changed(self, text):
        self.password_status.clear()
        self.form_status.clear()
    
    def on_login(self):
        self.login_button.setEnabled(False)
        self.login_button.setText("Signing In...")
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not username:
            self.username_status.set_error("Please enter your username or email")
            self._reset_login_button()
            return
        if not password:
            self.password_status.set_error("Please enter your password")
            self._reset_login_button()
            return
        QTimer.singleShot(400, lambda: self._perform_login(username, password))
    
    def _perform_login(self, username, password):
        try:
            success, user_id, uname = self.user_manager.login(username, password)
            if success:
                self.form_status.set_success("Login successful!")
                if self.remember_checkbox.isChecked():
                    self.user_manager.save_remembered_credentials(self.username_input.text().strip())
                else:
                    self.user_manager.clear_remembered_credentials()
                QTimer.singleShot(500, lambda: self.login_successful.emit(user_id, uname))
            else:
                self.form_status.set_error("Invalid username/email or password.")
                self._reset_login_button()
                self._shake_effect(self.form_frame) # Shake self.form_frame
        except Exception as e:
            self.form_status.set_error(f"Login error: {str(e)}")
            self._reset_login_button()

    def _reset_login_button(self):
            self.login_button.setEnabled(True)
            self.login_button.setText("Sign In")
    
    def _shake_effect(self, widget):
        # Placeholder for shake animation if needed
        pass

    def on_register(self): self.show_register.emit()
    def on_forgot_password(self): self.show_forgot_password.emit()
    
    def on_remember_me_changed(self, state):
        if not state: self.user_manager.clear_remembered_credentials()
    
    def clear_form(self):
        self.username_input.clear()
        self.password_input.clear()
        self.username_status.clear()
        self.password_status.clear()
        self.form_status.clear()
        self.remember_checkbox.setChecked(False)
        self._reset_login_button()
    
    def load_remembered_credentials(self):
        success, username_or_email = self.user_manager.load_remembered_credentials()
        if success and username_or_email:
            self.username_input.setText(username_or_email)
            self.remember_checkbox.setChecked(True)
            QTimer.singleShot(100, self.password_input.setFocus)

# RegistrationWidget (Adapted from auth_ui_register.py)
class RegistrationWidget(QWidget):
    registration_successful = pyqtSignal(str, str)
    show_login = pyqtSignal()
    
    def __init__(self, user_manager, parent=None):
        super().__init__(parent)
        self.user_manager = user_manager
        self.setup_fonts()
        self.init_ui()
    
    def setup_fonts(self): # Copied from LoginWidget for consistency
        self.title_font = QFont("SF Pro Display", 18, QFont.Bold)
        self.subtitle_font = QFont("SF Pro Text", 10)
        self.button_font = QFont("SF Pro Text", 10, QFont.Bold)
        # No material icons needed here based on original auth_ui_register.py
    
    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.setSpacing(20)
        main_layout.setAlignment(Qt.AlignCenter)

        # Logo (Placeholder)
        logo_label = QLabel("✨") 
        logo_label.setStyleSheet(f"font-size: 36px; color: {COLORS['primary']}; margin-bottom: 10px;")
        logo_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(logo_label)
        
        title_label = QLabel("Create Account")
        title_label.setFont(self.title_font)
        title_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 22px; font-weight: bold; margin-bottom: 5px;")
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)
        
        subtitle_label = QLabel("Join us today and get started")
        subtitle_label.setFont(self.subtitle_font)
        subtitle_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 14px; margin-bottom: 20px;")
        subtitle_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(subtitle_label)
        
        form_frame = QFrame()
        form_frame.setObjectName("auth_frame")
        form_frame.setMaximumWidth(450) # Wider for more fields
        apply_shadow(form_frame)
        
        form_layout_qfl = QFormLayout(form_frame) # Using QFormLayout for auto label alignment
        form_layout_qfl.setContentsMargins(25, 25, 25, 25)
        form_layout_qfl.setSpacing(10)
        form_layout_qfl.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)

        # Username
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Choose a username")
        self.username_input.setProperty("class", "auth_input")
        self.username_status = FormStatusLabel()
        username_container = QVBoxLayout()
        username_container.setSpacing(2)
        username_container.addWidget(self.username_input)
        username_container.addWidget(self.username_status)
        username_label_widget = QLabel("Username")
        username_label_widget.setProperty("class", "auth_field_label")
        form_layout_qfl.addRow(username_label_widget, username_container)
        
        # Email
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter your email address")
        self.email_input.setProperty("class", "auth_input")
        email_regex = QRegExp(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        self.email_input.setValidator(QRegExpValidator(email_regex))
        self.email_status = FormStatusLabel()
        email_container = QVBoxLayout()
        email_container.setSpacing(2)
        email_container.addWidget(self.email_input)
        email_container.addWidget(self.email_status)
        email_label_widget = QLabel("Email")
        email_label_widget.setProperty("class", "auth_field_label")
        form_layout_qfl.addRow(email_label_widget, email_container)

        # Password
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Create a strong password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setProperty("class", "auth_input")
        self.password_status = FormStatusLabel()
        self.password_strength = PasswordStrengthWidget()
        password_container = QVBoxLayout()
        password_container.setSpacing(2)
        password_container.addWidget(self.password_input)
        password_container.addWidget(self.password_status)
        password_container.addWidget(self.password_strength)
        password_label_widget = QLabel("Password")
        password_label_widget.setProperty("class", "auth_field_label")
        form_layout_qfl.addRow(password_label_widget, password_container)

        # Confirm Password
        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("Confirm your password")
        self.confirm_input.setEchoMode(QLineEdit.Password)
        self.confirm_input.setProperty("class", "auth_input")
        self.confirm_status = FormStatusLabel()
        confirm_container = QVBoxLayout()
        confirm_container.setSpacing(2)
        confirm_container.addWidget(self.confirm_input)
        confirm_container.addWidget(self.confirm_status)
        confirm_label_widget = QLabel("Confirm Password")
        confirm_label_widget.setProperty("class", "auth_field_label")
        form_layout_qfl.addRow(confirm_label_widget, confirm_container)
        
        self.form_status = FormStatusLabel() # General form errors
        self.form_status.setAlignment(Qt.AlignCenter)
        form_layout_qfl.addRow(self.form_status)

        self.terms_checkbox = QCheckBox("I agree to the Terms and Privacy Policy")
        self.terms_checkbox.setProperty("class", "auth_checkbox")
        self.terms_checkbox.setCursor(Qt.PointingHandCursor)
        form_layout_qfl.addRow(self.terms_checkbox)

        self.register_button = QPushButton("Create Account")
        self.register_button.setFont(self.button_font)
        self.register_button.setProperty("class", "auth_button_primary")
        self.register_button.setMinimumHeight(40)
        self.register_button.setCursor(Qt.PointingHandCursor)
        apply_shadow(self.register_button, 10, 0, 2)
        form_layout_qfl.addRow(self.register_button)
        
        main_layout.addWidget(form_frame, 0, Qt.AlignCenter)
        
        # Login link
        login_layout = QHBoxLayout()
        login_layout.setContentsMargins(0,15,0,0)
        login_label_text = QLabel("Already have an account?")
        login_label_text.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        login_button = QPushButton("Sign In")
        login_button.setProperty("class", "auth_button_text")
        login_button.setCursor(Qt.PointingHandCursor)
        login_button.clicked.connect(self.on_login_link) # Renamed to avoid clash
        login_layout.addStretch()
        login_layout.addWidget(login_label_text)
        login_layout.addWidget(login_button)
        login_layout.addStretch()
        main_layout.addLayout(login_layout)
        main_layout.addStretch()
        
        # Connections
        self.username_input.textChanged.connect(self.on_username_changed)
        self.email_input.textChanged.connect(self.on_email_changed)
        self.password_input.textChanged.connect(self.on_password_changed)
        self.confirm_input.textChanged.connect(self.on_confirm_changed)
        self.terms_checkbox.stateChanged.connect(self.on_terms_changed)
        self.register_button.clicked.connect(self.on_register)
    
    def on_username_changed(self, text):
        self.username_status.clear()
        self.form_status.clear()
        if text and not self.user_manager.validate_username(text):
            self.username_status.set_error("3-30 chars (letters, numbers, _, -)")
        elif text: # Check availability only if format is valid
            QTimer.singleShot(500, lambda: self._check_username_availability(text))


    def _check_username_availability(self, username):
        if username != self.username_input.text(): return # Value changed
        if self.user_manager.is_username_taken(username):
            self.username_status.set_error("Username already taken")
        else:
            self.username_status.set_success("Username available")

    
    def on_email_changed(self, text):
        self.email_status.clear()
        self.form_status.clear()
        if text and not self.user_manager.validate_email(text):
            self.email_status.set_error("Invalid email format")
        elif text: # Check availability
             QTimer.singleShot(500, lambda: self._check_email_availability(text))

    def _check_email_availability(self, email):
        if email != self.email_input.text(): return # Value changed
        if self.user_manager.is_email_taken(email):
            self.email_status.set_error("Email already registered")
        else:
            self.email_status.set_success("Email available")
    
    def on_password_changed(self, text):
        self.password_status.clear()
        self.form_status.clear()
        self.password_strength.update_strength(text)
        # Basic validation for immediate feedback
        validation = self.user_manager.validate_password(text)
        if text and not validation["valid"]:
             self.password_status.set_error("Weak: Use 8+ chars, A-Z, a-z, 0-9")
        elif text:
             self.password_status.set_success("Password format looks good")
        if self.confirm_input.text(): self.on_confirm_changed(self.confirm_input.text())

    
    def on_confirm_changed(self, text):
        self.confirm_status.clear()
        self.form_status.clear()
        if text and self.password_input.text() != text:
            self.confirm_status.set_error("Passwords do not match")
        elif text:
            self.confirm_status.set_success("Passwords match")

    def on_terms_changed(self, state): self.form_status.clear()
    
    def on_register(self):
        self.register_button.setEnabled(False)
        self.register_button.setText("Creating Account...")
        username = self.username_input.text().strip()
        email = self.email_input.text().strip()
        password = self.password_input.text()
        
        # Re-validate all fields before attempting registration
        if not self.user_manager.validate_username(username):
            self.username_status.set_error("Invalid username format/length")
            self._reset_register_button(); return
        if self.user_manager.is_username_taken(username):
            self.username_status.set_error("Username already taken")
            self._reset_register_button(); return
        if not self.user_manager.validate_email(email):
            self.email_status.set_error("Invalid email format")
            self._reset_register_button(); return
        if self.user_manager.is_email_taken(email):
            self.email_status.set_error("Email already registered")
            self._reset_register_button(); return
        
        password_validation = self.user_manager.validate_password(password)
        if not password_validation["valid"]:
            self.password_status.set_error("Password does not meet criteria")
            self._reset_register_button(); return
        if password != self.confirm_input.text():
            self.confirm_status.set_error("Passwords do not match")
            self._reset_register_button(); return
        if not self.terms_checkbox.isChecked():
            self.form_status.set_error("You must agree to the terms")
            self._reset_register_button(); return

        QTimer.singleShot(500, lambda: self._perform_registration(username, email, password))
    
    def _perform_registration(self, username, email, password):
        try:
            user_id = self.user_manager.register_user(username, email, password)
            self.form_status.set_success("Registration successful!")
            QTimer.singleShot(800, lambda: self.registration_successful.emit(user_id, username))
        except ValidationError as e:
            self.form_status.set_error(str(e))
            self._reset_register_button()
        except AuthError as e: # Handles "already taken" from register_user now
            self.form_status.set_error(str(e))
            self._reset_register_button()
        except Exception as e:
            self.form_status.set_error(f"Registration error: {str(e)}")
            self._reset_register_button()
    
    def _reset_register_button(self):
        self.register_button.setEnabled(True)
        self.register_button.setText("Create Account")
    
    def on_login_link(self): self.show_login.emit()
    
    def clear_form(self):
        self.username_input.clear()
        self.email_input.clear()
        self.password_input.clear()
        self.confirm_input.clear()
        self.username_status.clear()
        self.email_status.clear()
        self.password_status.clear()
        self.confirm_status.clear()
        self.form_status.clear()
        self.terms_checkbox.setChecked(False)
        self.password_strength.update_strength("")
        self._reset_register_button()

# ForgotPasswordWidget (Adapted from auth_ui_forgot.py)
class ForgotPasswordWidget(QWidget):
    password_reset_complete = pyqtSignal() # Emitted on successful password change
    show_login = pyqtSignal() # To go back to login screen
    
    def __init__(self, user_manager, parent=None):
        super().__init__(parent)
        self.user_manager = user_manager
        self.current_step = 0 # 0: email, 1: code, 2: new_password, 3: success
        self.reset_email_val = "" # Store email temporarily
        self.reset_code_val = ""  # Store code temporarily
        self.setup_fonts()
        self.init_ui()
    
    def setup_fonts(self):
        self.title_font = QFont("SF Pro Display", 18, QFont.Bold)
        self.subtitle_font = QFont("SF Pro Text", 10)
        self.button_font = QFont("SF Pro Text", 10, QFont.Bold)
    
    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40,40,40,40)
        main_layout.setSpacing(20)
        main_layout.setAlignment(Qt.AlignCenter)

        self.step_stack = QStackedWidget()
        self.email_widget = self._create_email_widget()
        self.code_widget = self._create_code_widget()
        self.password_widget = self._create_password_widget()
        self.success_widget = self._create_success_widget()

        self.step_stack.addWidget(self.email_widget)
        self.step_stack.addWidget(self.code_widget)
        self.step_stack.addWidget(self.password_widget)
        self.step_stack.addWidget(self.success_widget)
        
        main_layout.addWidget(self.step_stack)
        self.go_to_step(0) # Start at email step

    def _create_step_frame(self, title_text, subtitle_text, logo_char="🔑"):
        step_widget = QWidget()
        layout = QVBoxLayout(step_widget)
        layout.setContentsMargins(0,0,0,0) # No outer margins for the step_widget itself
        layout.setSpacing(20)
        layout.setAlignment(Qt.AlignCenter)

        if logo_char:
            logo_label = QLabel(logo_char)
            logo_label.setStyleSheet(f"font-size: 36px; color: {COLORS['primary']}; margin-bottom: 10px;")
            logo_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(logo_label)

        title_label_widget = QLabel(title_text)
        title_label_widget.setFont(self.title_font)
        title_label_widget.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 22px; font-weight: bold; margin-bottom: 5px;")
        title_label_widget.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label_widget)

        if subtitle_text:
            subtitle_label_widget = QLabel(subtitle_text)
            subtitle_label_widget.setFont(self.subtitle_font)
            subtitle_label_widget.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 14px; margin-bottom: 20px; max-width: 350px;")
            subtitle_label_widget.setAlignment(Qt.AlignCenter)
            subtitle_label_widget.setWordWrap(True)
            layout.addWidget(subtitle_label_widget)

        form_frame = QFrame()
        form_frame.setObjectName("auth_frame")
        form_frame.setMaximumWidth(400)
        apply_shadow(form_frame)
        layout.addWidget(form_frame, 0, Qt.AlignCenter)
        
        inner_form_layout = QVBoxLayout(form_frame) # This is where fields will go
        inner_form_layout.setContentsMargins(25,25,25,25)
        inner_form_layout.setSpacing(15)
        
        return step_widget, inner_form_layout # Return widget and layout to add fields

    def _create_email_widget(self):
        widget, form_layout = self._create_step_frame("Reset Password", "Enter your email address and we'll send you a code to reset your password.")
        
        email_label = QLabel("Email Address")
        email_label.setProperty("class", "auth_field_label")
        self.email_input_fp = QLineEdit() # fp for ForgotPassword
        self.email_input_fp.setPlaceholderText("Enter your registered email")
        self.email_input_fp.setProperty("class", "auth_input")
        self.email_status_fp = FormStatusLabel()
        form_layout.addWidget(email_label)
        form_layout.addWidget(self.email_input_fp)
        form_layout.addWidget(self.email_status_fp)

        self.email_next_button = QPushButton("Send Reset Code")
        self.email_next_button.setFont(self.button_font)
        self.email_next_button.setProperty("class", "auth_button_primary")
        self.email_next_button.setMinimumHeight(40)
        apply_shadow(self.email_next_button,10,0,2)
        form_layout.addWidget(self.email_next_button)
        
        back_button = QPushButton("Back to Login")
        back_button.setProperty("class", "auth_button_text")
        form_layout.addWidget(back_button, 0, Qt.AlignCenter)

        self.email_next_button.clicked.connect(self.on_email_next)
        back_button.clicked.connect(self.on_back_to_login_link)
        return widget
    
    def _create_code_widget(self):
        widget, form_layout = self._create_step_frame("Enter Verification Code", "We've sent a code to your email. Please enter it below.")
        self.code_instruction_label = widget.findChild(QLabel, None) # To update with actual code in demo
        
        code_label = QLabel("Verification Code")
        code_label.setProperty("class", "auth_field_label")
        self.code_input_fp = QLineEdit()
        self.code_input_fp.setPlaceholderText("Enter the 8-digit code")
        self.code_input_fp.setProperty("class", "auth_input")
        self.code_input_fp.setMaxLength(8) # As per auth_ui_forgot
        self.code_status_fp = FormStatusLabel()
        form_layout.addWidget(code_label)
        form_layout.addWidget(self.code_input_fp)
        form_layout.addWidget(self.code_status_fp)

        self.code_next_button = QPushButton("Verify Code")
        self.code_next_button.setFont(self.button_font)
        self.code_next_button.setProperty("class", "auth_button_primary")
        self.code_next_button.setMinimumHeight(40)
        apply_shadow(self.code_next_button,10,0,2)
        form_layout.addWidget(self.code_next_button)

        code_back_button = QPushButton("Back")
        code_back_button.setProperty("class", "auth_button_text")
        form_layout.addWidget(code_back_button, 0, Qt.AlignCenter)

        self.code_next_button.clicked.connect(self.on_code_next)
        code_back_button.clicked.connect(lambda: self.go_to_step(0))
        return widget
    
    def _create_password_widget(self):
        widget, form_layout = self._create_step_frame("Create New Password", "Create a new strong password for your account.")

        new_pass_label = QLabel("New Password")
        new_pass_label.setProperty("class", "auth_field_label")
        self.new_password_input_fp = QLineEdit()
        self.new_password_input_fp.setPlaceholderText("Create a strong password")
        self.new_password_input_fp.setEchoMode(QLineEdit.Password)
        self.new_password_input_fp.setProperty("class", "auth_input")
        self.new_password_strength_fp = PasswordStrengthWidget()
        form_layout.addWidget(new_pass_label)
        form_layout.addWidget(self.new_password_input_fp)
        form_layout.addWidget(self.new_password_strength_fp)
        
        confirm_pass_label = QLabel("Confirm New Password")
        confirm_pass_label.setProperty("class", "auth_field_label")
        self.confirm_password_input_fp = QLineEdit()
        self.confirm_password_input_fp.setPlaceholderText("Confirm your new password")
        self.confirm_password_input_fp.setEchoMode(QLineEdit.Password)
        self.confirm_password_input_fp.setProperty("class", "auth_input")
        self.confirm_password_status_fp = FormStatusLabel()
        form_layout.addWidget(confirm_pass_label)
        form_layout.addWidget(self.confirm_password_input_fp)
        form_layout.addWidget(self.confirm_password_status_fp)

        self.password_form_status_fp = FormStatusLabel()
        self.password_form_status_fp.setAlignment(Qt.AlignCenter)
        form_layout.addWidget(self.password_form_status_fp)

        self.reset_button_fp = QPushButton("Reset Password")
        self.reset_button_fp.setFont(self.button_font)
        self.reset_button_fp.setProperty("class", "auth_button_primary")
        self.reset_button_fp.setMinimumHeight(40)
        apply_shadow(self.reset_button_fp,10,0,2)
        form_layout.addWidget(self.reset_button_fp)

        password_back_button = QPushButton("Back")
        password_back_button.setProperty("class", "auth_button_text")
        form_layout.addWidget(password_back_button, 0, Qt.AlignCenter)
        
        self.new_password_input_fp.textChanged.connect(self.on_new_password_changed_fp)
        self.confirm_password_input_fp.textChanged.connect(self.on_confirm_password_changed_fp)
        self.reset_button_fp.clicked.connect(self.on_reset_password_fp)
        password_back_button.clicked.connect(lambda: self.go_to_step(1))
        return widget
    
    def _create_success_widget(self):
        widget, form_layout = self._create_step_frame("Password Reset Successfully!", 
                                                      "You can now log in with your new password.", 
                                                      logo_char="✓")
        # Adjust success logo style
        success_icon_label = widget.findChild(QLabel) # First QLabel is the logo
        if success_icon_label:
            success_icon_label.setStyleSheet(f"font-size: 48px; color: {COLORS['success']}; margin-bottom: 10px;")


        login_button = QPushButton("Return to Login")
        login_button.setFont(self.button_font)
        login_button.setProperty("class", "auth_button_primary")
        login_button.setMinimumHeight(40)
        apply_shadow(login_button,10,0,2)
        form_layout.addWidget(login_button, 0, Qt.AlignCenter)
        
        login_button.clicked.connect(self.on_back_to_login_link)
        return widget
    
    def go_to_step(self, step_index):
        self.current_step = step_index
        self.step_stack.setCurrentIndex(step_index)
        # Clear relevant status labels
        if step_index == 0: self.email_status_fp.clear()
        elif step_index == 1: self.code_status_fp.clear()
        elif step_index == 2:
            self.password_form_status_fp.clear()
            self.confirm_password_status_fp.clear()
            self.new_password_strength_fp.update_strength("")


    def on_email_next(self):
        self.email_next_button.setEnabled(False)
        self.email_next_button.setText("Sending...")
        email = self.email_input_fp.text().strip()
        self.reset_email_val = email # Store it

        if not email:
            self.email_status_fp.set_error("Please enter your email")
            self._reset_button_state(self.email_next_button, "Send Reset Code")
            return
        if not self.user_manager.validate_email(email):
            self.email_status_fp.set_error("Invalid email format")
            self._reset_button_state(self.email_next_button, "Send Reset Code")
            return
        
        QTimer.singleShot(800, lambda: self._process_email_request(email))
    
    def _process_email_request(self, email):
            success, reset_code = self.user_manager.generate_reset_code(email)
            if success:
                self.reset_code_val = reset_code
                # Update instruction with the code (for demo purposes)
                # Find the subtitle label in the code_widget to update it
                subtitle_label = self.code_widget.findChildren(QLabel)[1] # Assuming second QLabel is subtitle
                if subtitle_label:
                     subtitle_label.setText(f"""We\\'ve sent a verification code to {email}.
For this demo, use this code: {reset_code}""")

                self._reset_button_state(self.email_next_button, "Send Reset Code")
                self.go_to_step(1)
            else:
                self.email_status_fp.set_error("Email not found in our records")
                self._reset_button_state(self.email_next_button, "Send Reset Code")

    def on_code_next(self):
        self.code_next_button.setEnabled(False)
        self.code_next_button.setText("Verifying...")
        code = self.code_input_fp.text().strip().upper()
        
        if not code:
            self.code_status_fp.set_error("Please enter the code")
            self._reset_button_state(self.code_next_button, "Verify Code")
            return
        
        QTimer.singleShot(800, lambda: self._process_code_verification(code))

    def _process_code_verification(self, code):
        success, user_id = self.user_manager.verify_reset_code(code)
        if success:
            # Store verified code (already done if generate_reset_code was successful and it's the same code)
            self.reset_code_val = code 
            self._reset_button_state(self.code_next_button, "Verify Code")
            self.go_to_step(2)
        else:
            self.code_status_fp.set_error("Invalid or expired code")
            self._reset_button_state(self.code_next_button, "Verify Code")

    def on_new_password_changed_fp(self, text):
        self.password_form_status_fp.clear()
        self.new_password_strength_fp.update_strength(text)
        if self.confirm_password_input_fp.text():
            self.on_confirm_password_changed_fp(self.confirm_password_input_fp.text())

    def on_confirm_password_changed_fp(self, text):
        self.confirm_password_status_fp.clear()
        if text and self.new_password_input_fp.text() != text:
            self.confirm_password_status_fp.set_error("Passwords do not match")
        elif text:
            self.confirm_password_status_fp.set_success("Passwords match")
    
    def on_reset_password_fp(self):
        self.reset_button_fp.setEnabled(False)
        self.reset_button_fp.setText("Resetting...")
        new_password = self.new_password_input_fp.text()

        if not self.user_manager.validate_password(new_password)["valid"]:
            self.password_form_status_fp.set_error("Password criteria not met")
            self._reset_button_state(self.reset_button_fp, "Reset Password")
            return
        if new_password != self.confirm_password_input_fp.text():
            self.confirm_password_status_fp.set_error("Passwords do not match")
            self._reset_button_state(self.reset_button_fp, "Reset Password")
            return
        
        QTimer.singleShot(1000, lambda: self._process_password_reset(new_password))
    
    def _process_password_reset(self, new_password):
        try:
            success = self.user_manager.reset_password(self.reset_code_val, new_password)
            if success:
                self._reset_button_state(self.reset_button_fp, "Reset Password")
                self.go_to_step(3) # Success screen
                self.password_reset_complete.emit() # Signal completion
            else: # Should not happen if reset_password raises errors
                self.password_form_status_fp.set_error("Failed to reset password")
                self._reset_button_state(self.reset_button_fp, "Reset Password")
        except ValidationError as e:
            self.password_form_status_fp.set_error(str(e))
            self._reset_button_state(self.reset_button_fp, "Reset Password")
        except AuthError as e:
            self.password_form_status_fp.set_error(str(e)) # e.g. invalid code if logic allows re-check
            self._reset_button_state(self.reset_button_fp, "Reset Password")


    def _reset_button_state(self, button, text):
        button.setEnabled(True)
        button.setText(text)
    
    def on_back_to_login_link(self):
        self.clear_form() # Clear before emitting
        self.show_login.emit()
    
    def clear_form(self):
        self.email_input_fp.clear()
        self.email_status_fp.clear()
        self._reset_button_state(self.email_next_button, "Send Reset Code")
        
        self.code_input_fp.clear()
        self.code_status_fp.clear()
        self._reset_button_state(self.code_next_button, "Verify Code")
        # Reset code instruction label if it was modified
        subtitle_label = self.code_widget.findChildren(QLabel)[1]
        if subtitle_label:
            subtitle_label.setText("We've sent a code to your email. Please enter it below.")


        self.new_password_input_fp.clear()
        self.new_password_strength_fp.update_strength("")
        self.confirm_password_input_fp.clear()
        self.confirm_password_status_fp.clear()
        self.password_form_status_fp.clear()
        self._reset_button_state(self.reset_button_fp, "Reset Password")
        
        self.reset_email_val = ""
        self.reset_code_val = ""
        self.go_to_step(0)

# AuthenticationManager (Adapted from auth_manager.py)
class AuthenticationManager(QWidget):
    auth_successful = pyqtSignal(str, str)
    auth_logout = pyqtSignal()
    
    def __init__(self, parent=None, data_path=None): # data_path for UserManager
        super().__init__(parent)
        self.user_manager = UserManager(data_path) # Pass data_path
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0,0,0,0)
        main_layout.setSpacing(0)
        
        self.auth_stack = QStackedWidget()
        self.login_screen = LoginWidget(self.user_manager)
        self.register_screen = RegistrationWidget(self.user_manager)
        self.forgot_password_screen = ForgotPasswordWidget(self.user_manager)
        # No "authenticated_screen" here; PentoraAuthApp handles post-auth UI
        
        self.auth_stack.addWidget(self.login_screen)
        self.auth_stack.addWidget(self.register_screen)
        self.auth_stack.addWidget(self.forgot_password_screen)
        main_layout.addWidget(self.auth_stack)
        
        # Connections
        self.login_screen.login_successful.connect(self.on_internal_auth_successful)
        self.login_screen.show_register.connect(self.show_register)
        self.login_screen.show_forgot_password.connect(self.show_forgot_password)
        
        self.register_screen.registration_successful.connect(self.on_internal_auth_successful)
        self.register_screen.show_login.connect(self.show_login)
        
        self.forgot_password_screen.show_login.connect(self.show_login)
        self.forgot_password_screen.password_reset_complete.connect(self.show_login_after_reset)

        self.show_login() # Initial screen
    
    def show_login(self):
        self.login_screen.clear_form()
        self.login_screen.load_remembered_credentials()
        self.auth_stack.setCurrentWidget(self.login_screen)
        
    def show_login_after_reset(self): # User explicitly clicks "Return to Login" from success screen
        self.login_screen.clear_form() # Ensure login form is clean
        # Optionally, could pre-fill email if self.forgot_password_screen.reset_email_val is accessible and desired
        self.auth_stack.setCurrentWidget(self.login_screen)
    

    def show_register(self):
        self.register_screen.clear_form()
        self.auth_stack.setCurrentWidget(self.register_screen)
    
    def show_forgot_password(self):
        self.forgot_password_screen.clear_form()
        self.auth_stack.setCurrentWidget(self.forgot_password_screen)
    
    def on_internal_auth_successful(self, user_id, username):
        # This now just bubbles up the signal
        self.auth_successful.emit(user_id, username)
    
    def perform_logout(self): # Renamed to distinguish from signal
        self.user_manager.logout()
        self.show_login() # Ensure login screen is shown internally
        self.auth_logout.emit() # Signal that logout happened

    def get_user_manager(self): return self.user_manager
    def is_authenticated(self): return self.user_manager.is_logged_in()
    def get_current_user(self): return self.user_manager.get_current_user()


# PentoraAuthApp (Main Application Window)
class PentoraAuthApp(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.apply_global_styles()
    
    def init_ui(self):
        self.setWindowTitle("Pentora")
        self.setMinimumSize(900, 700) # Adjusted min height
        self.resize(1280, 800) # Default size

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0,0,0,0)
        self.main_layout.setSpacing(0)
        
        # Header
        self.header_widget = QFrame()
        self.header_widget.setFixedHeight(60) # Adjusted height
        self.header_widget.setObjectName("app_header") # For styling
        header_layout = QHBoxLayout(self.header_widget)
        header_layout.setContentsMargins(15,0,15,0)

        app_logo_label = QLabel("PENTORA") # Could be an image
        app_logo_label.setStyleSheet(f"color: {COLORS['primary']}; font-size: 20px; font-weight: bold;")
        header_layout.addWidget(app_logo_label)
        header_layout.addStretch()

        self.user_button = QPushButton("Not Logged In")
        self.user_button.setFlat(True)
        self.user_button.setCursor(Qt.PointingHandCursor)
        self.user_button.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 13px; padding: 5px;")
        self.user_menu = QMenu(self)
        self.user_button.setMenu(self.user_menu)
        self.user_button.setVisible(False) # Initially hidden
        header_layout.addWidget(self.user_button)
        
        self.main_layout.addWidget(self.header_widget)

        # Content Stack (Auth Screens or Main App)
        self.content_stack = QStackedWidget()
        self.auth_manager_widget = AuthenticationManager() # data_path can be passed if needed
        self.main_gui_widget = None # lazy loaded

        self.content_stack.addWidget(self.auth_manager_widget)
        self.main_layout.addWidget(self.content_stack)

        # Connections
        self.auth_manager_widget.auth_successful.connect(self.on_auth_flow_successful)
        self.auth_manager_widget.auth_logout.connect(self.on_auth_flow_logout) # Connected to signal from AuthManager
        
        # Check initial login state (e.g. remembered user)
        if self.auth_manager_widget.is_authenticated():
            current_user = self.auth_manager_widget.get_current_user()
            self.on_auth_flow_successful(current_user["user_id"], current_user["username"])
        else:
            self.content_stack.setCurrentWidget(self.auth_manager_widget)


    def apply_global_styles(self):
        # Global styles for the entire application window and specific auth components
        # This assumes STYLE_SHEETS uses specific selectors like #auth_frame, .auth_input
        # It also styles elements like QMainWindow, QFrame#app_header directly.
        base_font_family = "'SF Pro Display', 'Helvetica Neue', Arial, sans-serif"
        
        global_stylesheet = f"""
            QMainWindow {{
                background-color: {COLORS["background"]};
                color: {COLORS["text_primary"]};
                font-family: {base_font_family};
                font-size: 10pt;
            }}
            QFrame#app_header {{
                background-color: {COLORS["surface"]};
                border-bottom: 1px solid {COLORS["border"]};
            }}
            QStackedWidget {{ /* General stack widget, might need to be more specific if it affects main_gui */
                background-color: transparent;
            }}
            AuthenticationManager {{ /* Style the AuthenticationManager widget itself if needed */
                background-color: transparent; 
            }}
            /* Import styles from the STYLE_SHEETS dictionary */
            {STYLE_SHEETS["container_frame"]}
            {STYLE_SHEETS["title_label"]}
            {STYLE_SHEETS["subtitle_label"]}
            {STYLE_SHEETS["field_label"]}
            {STYLE_SHEETS["line_edit"]}
            {STYLE_SHEETS["primary_button"]}
            {STYLE_SHEETS["secondary_button"]}
            {STYLE_SHEETS["text_button"]}
            {STYLE_SHEETS["checkbox"]}
            
            /* Style for QMenu */
            QMenu {{
                background-color: {COLORS["surface"]};
                color: {COLORS["text_primary"]};
                border: 1px solid {COLORS["border"]};
                padding: 5px;
                font-size: 12px;
            }}
            QMenu::item {{
                padding: 8px 20px 8px 20px;
                min-width: 100px;
            }}
            QMenu::item:selected {{
                background-color: {COLORS["primary"]};
                color: {COLORS["text_light"]};
            }}
            QMenu::separator {{
                height: 1px;
                background: {COLORS["border"]};
                margin-left: 10px;
                margin-right: 5px;
            }}
        """
        self.setStyleSheet(global_stylesheet)

    def on_auth_flow_successful(self, user_id, username):
        if self.main_gui_widget is None:
            try:
                self.main_gui_widget = PentoraMainWindow() # Create main app UI
                self.content_stack.addWidget(self.main_gui_widget)
            except Exception as e:
                logging.error(f"Failed to initialize PentoraMainWindow: {e}")
                QMessageBox.critical(self, "Error", f"Could not load the main application UI: {e}")
                # Potentially log out the user or show an error screen
                self.auth_manager_widget.perform_logout() # Log out if main UI fails
                return
                
        self.content_stack.setCurrentWidget(self.main_gui_widget)
        self.user_button.setText(username)
        self.user_menu.clear()
        sign_out_action = self.user_menu.addAction("Sign Out")
        # sign_out_action.triggered.connect(self.auth_manager_widget.perform_logout) # Connect directly
        sign_out_action.triggered.connect(self._request_logout_from_menu) # Use an intermediate method
        self.user_button.setVisible(True)

    def _request_logout_from_menu(self):
        # This method is specifically for the menu action.
        # It calls perform_logout on the auth_manager_widget.
        # perform_logout will handle user_manager.logout(), show_login(), and emit auth_logout.
        self.auth_manager_widget.perform_logout()


    def on_auth_flow_logout(self):
        # This is connected to the auth_logout signal from AuthenticationManager
        # It handles UI changes in PentoraAuthApp after logout is confirmed
        self.user_button.setVisible(False)
        self.user_menu.clear()
        self.content_stack.setCurrentWidget(self.auth_manager_widget)
        # auth_manager_widget.show_login() is already called by its perform_logout

# Main application entry point
def main():
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    app = QApplication(sys.argv)
    app.setApplicationName("Pentora")
    app.setApplicationDisplayName("Pentora")
    
    # Set consistent base font
    default_font = QFont("SF Pro Text", 10) # Or another suitable default
    app.setFont(default_font)
    
    # Set application icon
    icon_path = get_app_icon_path()
    if icon_path and os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    else:
        logging.warning(f"Application icon not found at: {icon_path}")

    window = PentoraAuthApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main() 