#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Pentora - Authentication UI components - Enhanced UI
# Copyright (C) 2025 Pentora Team

from PyQt5.QtWidgets import (
    QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, 
    QStackedWidget, QFormLayout, QFrame, QCheckBox, QProgressBar, 
    QMessageBox, QSpacerItem, QSizePolicy, QGraphicsDropShadowEffect
)
from PyQt5.QtCore import Qt, pyqtSignal, QRegExp, QTimer, QPropertyAnimation, QEasingCurve, QPoint, QSize
from PyQt5.QtGui import (
    QRegExpValidator, QIcon, QColor, QPixmap, QFont, QPainter, 
    QLinearGradient, QBrush, QFontDatabase, QCursor
)

from .auth import UserManager, ValidationError, AuthError

# Modern color palette with dark theme
COLORS = {
    "primary": "#6C63FF",      # Main accent color (vibrant purple)
    "primary_hover": "#5A52D9", # Primary hover state
    "primary_active": "#4A44B2", # Primary active state
    "secondary": "#07B89E",    # Secondary accent (teal)
    "secondary_hover": "#06A790", # Secondary hover
    "secondary_light": "#B0F4E6", # Light teal for highlights
    "danger": "#FF6B6B",       # Error/danger color (soft red)
    "success": "#4ECB71",      # Success color (green)
    "warning": "#FFBE0B",      # Warning color (amber)
    "info": "#4FC3F7",         # Info color (light blue)
    "text_primary": "#E0E0E0", # Primary text on dark bg
    "text_secondary": "#9E9E9E", # Secondary text on dark bg
    "text_light": "#FFFFFF",   # Text on dark bg
    "text_muted": "#757575",   # Muted text
    "background": "#252525",   # Main dark background
    "surface": "#303030",      # Surface/card dark background
    "border": "#424242",       # Border color for dark theme
    "border_focus": "#6C63FF", # Border color when focused
    "divider": "#424242",      # Divider color for dark theme
    "shadow": "#12121280",     # Shadow color with alpha for dark theme
}

# Enhanced base styles for common widgets
STYLE_SHEETS = {
    "app": f"""
        QWidget {{
            font-family: 'SF Pro Display', 'Helvetica Neue', 'Arial';
            font-size: 10pt;
            color: {COLORS["text_primary"]};
            background-color: {COLORS["background"]};
        }}
    """,
    "container_frame": f"""
        QFrame {{
            background-color: {COLORS["surface"]};
            border-radius: 10px;
            border: 1px solid {COLORS["border"]};
        }}
    """,
    "title_label": f"""
        QLabel {{
            color: {COLORS["primary"]};
            font-size: 22px;
            font-weight: bold;
            margin-bottom: 15px;
        }}
    """,
    "subtitle_label": f"""
        QLabel {{
            color: {COLORS["text_secondary"]};
            font-size: 14px;
            margin-bottom: 10px;
        }}
    """,
    "field_label": f"""
        QLabel {{
            color: {COLORS["text_secondary"]};
            font-size: 12px;
            font-weight: 600;
            margin-bottom: 4px;
        }}
    """,
    "line_edit": f"""
        QLineEdit {{
            background-color: {COLORS["surface"]};
            color: {COLORS["text_primary"]};
            border: 1px solid {COLORS["border"]};
            border-radius: 6px;
            padding: 10px 12px;
            font-size: 12px;
            min-height: 20px;
        }}
        QLineEdit:focus {{
            border: 2px solid {COLORS["primary"]};
            background-color: {COLORS["surface"]};
        }}
        QLineEdit:hover:!focus {{
            border: 1px solid #555555;
        }}
        QLineEdit[echoMode="2"] {{
            lineedit-password-character: 9679;
        }}
        QLineEdit:disabled {{
            background-color: {COLORS["background"]};
            color: {COLORS["text_muted"]};
        }}
    """,
    "primary_button": f"""
        QPushButton {{
            background-color: {COLORS["primary"]};
            color: {COLORS["text_light"]};
            font-weight: bold;
            border: none;
            border-radius: 6px;
            padding: 10px 16px;
            min-height: 20px;
            font-size: 13px;
        }}
        QPushButton:hover {{
            background-color: {COLORS["primary_hover"]};
        }}
        QPushButton:pressed {{
            background-color: {COLORS["primary_active"]};
        }}
        QPushButton:disabled {{
            background-color: #CCCCCC;
            color: #666666;
        }}
    """,
    "secondary_button": f"""
        QPushButton {{
            background-color: {COLORS["surface"]};
            color: {COLORS["primary"]};
            border: 1px solid {COLORS["primary"]};
            border-radius: 6px;
            padding: 10px 16px;
            min-height: 20px;
            font-size: 13px;
        }}
        QPushButton:hover {{
            background-color: {COLORS["primary"] + "10"};
        }}
        QPushButton:pressed {{
            background-color: {COLORS["primary"] + "20"};
        }}
    """,
    "text_button": f"""
        QPushButton {{
            background-color: transparent;
            color: {COLORS["primary"]};
            border: none;
            text-decoration: none;
            padding: 5px;
            font-size: 12px;
        }}
        QPushButton:hover {{
            color: {COLORS["primary_hover"]};
            text-decoration: underline;
        }}
        QPushButton:pressed {{
            color: {COLORS["primary_active"]};
        }}
    """,
    "checkbox": f"""
        QCheckBox {{
            color: {COLORS["text_secondary"]};
            font-size: 12px;
            spacing: 8px;
        }}
        QCheckBox::indicator {{
            width: 18px;
            height: 18px;
            border-radius: 4px;
            border: 1px solid {COLORS["border"]};
            background-color: {COLORS["background"]};
        }}
        QCheckBox::indicator:unchecked:hover {{
            border: 1px solid {COLORS["primary"]};
        }}
        QCheckBox::indicator:checked {{
            background-color: {COLORS["primary"]};
            border: 1px solid {COLORS["primary"]};
            image: url(:/icons/check.png);
        }}
    """,
}

# Function to apply a drop shadow to a widget
def apply_shadow(widget, radius=15, x_offset=0, y_offset=3, color=COLORS["shadow"]):
    """Apply a drop shadow effect to a widget"""
    shadow = QGraphicsDropShadowEffect(widget)
    shadow.setBlurRadius(radius)
    shadow.setColor(QColor(color))
    shadow.setOffset(x_offset, y_offset)
    widget.setGraphicsEffect(shadow)

class PasswordStrengthWidget(QWidget):
    """Widget for showing password strength with enhanced visual design"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        
        # Strength bar with modern design
        self.strength_bar = QProgressBar()
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(0)
        self.strength_bar.setFixedHeight(6)
        self.strength_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: {COLORS["divider"]};
                border: none;
                border-radius: 3px;
            }}
            QProgressBar::chunk {{
                background-color: {COLORS["primary"]};
                border-radius: 3px;
            }}
        """)
        layout.addWidget(self.strength_bar)
        
        # Use a grid for more compact requirements layout
        requirements_layout = QHBoxLayout()
        requirements_layout.setContentsMargins(0, 5, 0, 0)
        requirements_layout.setSpacing(8)
        
        # Create more compact requirement labels
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
        """Create a label for password requirement with enhanced styling"""
        label = QLabel(f"❌ {text}")
        label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 10px;")
        return label
    
    def update_strength(self, password):
        """Update the password strength display with improved visual feedback"""
        if not password:
            self.strength_bar.setValue(0)
            self._update_requirement(self.req_length, False)
            self._update_requirement(self.req_uppercase, False)
            self._update_requirement(self.req_lowercase, False)
            self._update_requirement(self.req_number, False)
            
            # Set neutral color
            self.strength_bar.setStyleSheet(f"""
                QProgressBar {{
                    background-color: {COLORS["divider"]};
                    border: none;
                    border-radius: 3px;
                }}
                QProgressBar::chunk {{
                    background-color: {COLORS["text_muted"]};
                    border-radius: 3px;
                }}
            """)
            return
        
        # Check individual requirements
        length_ok = len(password) >= 8
        uppercase_ok = any(c.isupper() for c in password)
        lowercase_ok = any(c.islower() for c in password)
        number_ok = any(c.isdigit() for c in password)
        
        # Update requirement indicators with modern checkmarks/crosses
        self._update_requirement(self.req_length, length_ok)
        self._update_requirement(self.req_uppercase, uppercase_ok)
        self._update_requirement(self.req_lowercase, lowercase_ok)
        self._update_requirement(self.req_number, number_ok)
        
        # Calculate strength percentage
        strength = 0
        if length_ok: strength += 25
        if uppercase_ok: strength += 25
        if lowercase_ok: strength += 25
        if number_ok: strength += 25
        
        # Set color based on strength with nice gradient effect
        if strength < 50:
            color = COLORS["danger"]  # Red for weak passwords
        elif strength < 75:
            color = COLORS["warning"]  # Yellow for medium passwords
        elif strength < 100:
            color = COLORS["secondary"]  # Teal for good passwords
        else:
            color = COLORS["success"]  # Green for strong passwords
            
        self.strength_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: {COLORS["divider"]};
                border: none;
                border-radius: 3px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 3px;
            }}
        """)
        
        # Animate the progress bar for a smoother experience
        self.strength_bar.setValue(0)
        QTimer.singleShot(50, lambda: self.strength_bar.setValue(strength))
    
    def _update_requirement(self, label, is_met):
        """Update a requirement label to show if it's met with nicer symbols"""
        if is_met:
            label.setText(label.text().replace("❌", "✓"))
            label.setStyleSheet(f"color: {COLORS['success']}; font-size: 11px;")
        else:
            label.setText(label.text().replace("✓", "❌"))
            label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px;")


class FormStatusLabel(QLabel):
    """Label for showing form validation status with enhanced styling"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setFixedHeight(16)  # Fixed height to avoid layout shifts
        self.clear()
    
    def clear(self):
        """Clear the status label"""
        self.setText("")
        self.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; padding: 0px;")
        self.setVisible(False)  # Hide completely when cleared
    
    def set_error(self, message):
        """Set an error message with improved error styling"""
        self.setText(f"❌ {message}")
        self.setStyleSheet(f"color: {COLORS['danger']}; font-size: 11px; padding: 0px;")
        self.setVisible(True)
    
    def set_success(self, message):
        """Set a success message with improved success styling"""
        self.setText(f"✓ {message}")
        self.setStyleSheet(f"color: {COLORS['success']}; font-size: 11px; padding: 0px;")
        self.setVisible(True)
    
    def set_info(self, message):
        """Set an information message with improved info styling"""
        self.setText(f"ℹ️ {message}")
        self.setStyleSheet(f"color: {COLORS['info']}; font-size: 11px; padding: 0px;")
        self.setVisible(True)


class LoginWidget(QWidget):
    """Login screen widget with enhanced modern UI"""
    
    # Signals
    login_successful = pyqtSignal(str, str)  # user_id, username
    show_register = pyqtSignal()
    show_forgot_password = pyqtSignal()
    
    def __init__(self, user_manager, parent=None):
        super().__init__(parent)
        self.user_manager = user_manager
        
        # Initialize fonts
        self.setup_fonts()
        
        # Initialize the modernized UI
        self.init_ui()
        
        # Check for remembered credentials
        self.load_remembered_credentials()
    
    def setup_fonts(self):
        """Setup custom fonts for a more modern look"""
        # Load system fonts or default to standard ones
        self.title_font = QFont()
        self.title_font.setFamily("SF Pro Display")
        self.title_font.setPointSize(18)
        self.title_font.setBold(True)
        
        self.subtitle_font = QFont()
        self.subtitle_font.setFamily("SF Pro Text")
        self.subtitle_font.setPointSize(10)
        
        self.button_font = QFont()
        self.button_font.setFamily("SF Pro Text")
        self.button_font.setPointSize(10)
        self.button_font.setBold(True)
        
        # Load Material Icons font for visibility toggle
        self.material_icons_font = QFont("Material Icons")
        if "Material Icons" not in QFontDatabase().families():
            font_id = QFontDatabase.addApplicationFont(
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources", "fonts", "MaterialIcons-Regular.ttf")
            )
            if font_id == -1:
                print("Failed to load Material Icons font")
            else:
                self.material_icons_font = QFontDatabase.applicationFontFamilies(font_id)[0]
    
    def init_ui(self):
        """Initialize the user interface with modern styling"""
        # Main layout with better spacing
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.setSpacing(20)
        
        # Create logo/icon (optional)
        logo_container = QWidget()
        logo_layout = QHBoxLayout(logo_container)
        logo_layout.setContentsMargins(0, 0, 0, 5)
        
        logo_label = QLabel()
        logo_label.setText("🔐")  # Lock emoji as placeholder, replace with actual logo
        logo_label.setStyleSheet("font-size: 42px; color: #6C63FF;")
        logo_label.setAlignment(Qt.AlignCenter)
        logo_layout.addWidget(logo_label)
        
        main_layout.addWidget(logo_container)
        
        # Title with modern font and styling
        title_label = QLabel("Welcome Back")
        title_label.setFont(self.title_font)
        title_label.setStyleSheet(STYLE_SHEETS["title_label"])
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("Sign in to continue")
        subtitle_label.setFont(self.subtitle_font)
        subtitle_label.setStyleSheet(STYLE_SHEETS["subtitle_label"])
        subtitle_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(subtitle_label)
        
        # Form frame
        form_frame = QFrame()
        form_frame.setStyleSheet(STYLE_SHEETS["container_frame"])
        form_layout = QVBoxLayout(form_frame)
        form_layout.setContentsMargins(25, 25, 25, 25)
        form_layout.setSpacing(10)
        
        # Username/Email field with better layout and styling
        username_layout = QVBoxLayout()
        username_layout.setContentsMargins(0, 0, 0, 0)
        username_layout.setSpacing(2)
        
        username_label = QLabel("Username or Email")
        username_label.setStyleSheet(STYLE_SHEETS["field_label"])
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username or email")
        self.username_input.setStyleSheet(STYLE_SHEETS["line_edit"])
        self.username_input.setCursor(QCursor(Qt.IBeamCursor))
        
        self.username_status = FormStatusLabel()
        
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_input)
        username_layout.addWidget(self.username_status)
        
        # Password field with better layout and styling
        password_layout = QVBoxLayout()
        password_layout.setContentsMargins(0, 5, 0, 0)
        password_layout.setSpacing(2)
        
        password_label = QLabel("Password")
        password_label.setStyleSheet(STYLE_SHEETS["field_label"])
        
        # Create a horizontal layout for password input and visibility toggle
        password_input_layout = QHBoxLayout()
        password_input_layout.setContentsMargins(0, 0, 0, 0)
        password_input_layout.setSpacing(0)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet(STYLE_SHEETS["line_edit"])
        self.password_input.setCursor(QCursor(Qt.IBeamCursor))
        
        # Create visibility toggle button
        self.visibility_button = QPushButton()
        self.visibility_button.setFixedSize(24, 24)
        self.visibility_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.visibility_button.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                padding: 0;
                margin: 0;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 0.1);
            }
        """)
        self.visibility_button.clicked.connect(self.toggle_password_visibility)
        self.update_visibility_icon()
        
        password_input_layout.addWidget(self.password_input)
        password_input_layout.addWidget(self.visibility_button)
        
        self.password_status = FormStatusLabel()
        
        password_layout.addWidget(password_label)
        password_layout.addLayout(password_input_layout)
        password_layout.addWidget(self.password_status)
        
        # Form status - zero height when empty
        self.form_status = FormStatusLabel()
        self.form_status.setAlignment(Qt.AlignCenter)
        
        # Remember me checkbox with modern styling
        remember_layout = QHBoxLayout()
        remember_layout.setContentsMargins(0, 5, 0, 5)
        self.remember_checkbox = QCheckBox("Remember me")
        self.remember_checkbox.setStyleSheet(STYLE_SHEETS["checkbox"])
        self.remember_checkbox.setCursor(QCursor(Qt.PointingHandCursor))
        self.remember_checkbox.stateChanged.connect(self.on_remember_me_changed)
        
        forgot_button = QPushButton("Forgot Password?")
        forgot_button.setStyleSheet(STYLE_SHEETS["text_button"])
        forgot_button.setCursor(QCursor(Qt.PointingHandCursor))
        forgot_button.clicked.connect(self.on_forgot_password)
        
        remember_layout.addWidget(self.remember_checkbox)
        remember_layout.addStretch()
        remember_layout.addWidget(forgot_button)
        
        # Login button with modern styling and hover effects
        self.login_button = QPushButton("Sign In")
        self.login_button.setFont(self.button_font)
        self.login_button.setStyleSheet(STYLE_SHEETS["primary_button"])
        self.login_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.login_button.clicked.connect(self.on_login)
        self.login_button.setMinimumHeight(48)
        
        # Register link with modern styling
        register_layout = QHBoxLayout()
        register_layout.setContentsMargins(0, 8, 0, 0)
        register_label = QLabel("Don't have an account?")
        register_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        
        register_button = QPushButton("Sign Up")
        register_button.setStyleSheet(STYLE_SHEETS["text_button"])
        register_button.setCursor(QCursor(Qt.PointingHandCursor))
        register_button.clicked.connect(self.on_register)
        
        register_layout.addStretch()
        register_layout.addWidget(register_label)
        register_layout.addWidget(register_button)
        register_layout.addStretch()
        
        # Add all form elements
        form_layout.addLayout(username_layout)
        form_layout.addLayout(password_layout)
        form_layout.addWidget(self.form_status)
        form_layout.addLayout(remember_layout)
        form_layout.addWidget(self.login_button)
        form_layout.addLayout(register_layout)
        
        # Add form to main layout
        main_layout.addWidget(form_frame)
        main_layout.addStretch()
        
        # Connect events
        self.username_input.textChanged.connect(self.on_username_changed)
        self.password_input.textChanged.connect(self.on_password_changed)
        self.password_input.returnPressed.connect(self.on_login)  # Allow Enter key
        self.username_input.returnPressed.connect(lambda: self.password_input.setFocus())
        
        # Set tab order
        self.setTabOrder(self.username_input, self.password_input)
        self.setTabOrder(self.password_input, self.remember_checkbox)
        self.setTabOrder(self.remember_checkbox, self.login_button)
    
    def on_username_changed(self, text):
        """Handle username field change"""
        self.username_status.clear()
        self.form_status.clear()

    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.password_input.echoMode() == QLineEdit.Password:
            self.password_input.setEchoMode(QLineEdit.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
        self.update_visibility_icon()

    def update_visibility_icon(self):
        """Update the visibility toggle icon"""
        if self.password_input.echoMode() == QLineEdit.Password:
            icon = "visibility_off"
        else:
            icon = "visibility"
        
        self.visibility_button.setFont(self.material_icons_font)
        self.visibility_button.setText(icon)
        self.visibility_button.setStyleSheet(
            f"""
            QPushButton {{
                background-color: transparent;
                border: none;
                padding: 0;
                margin: 0;
                color: {COLORS['text_secondary']};
            }}
            QPushButton:hover {{
                background-color: rgba(255, 255, 255, 0.1);
            }}
            """
        )
    
    def on_password_changed(self, text):
        """Handle password field change"""
        self.password_status.clear()
        self.form_status.clear()
    
    def on_login(self):
        """Attempt to log in with enhanced feedback"""
        # Add animation to button for feedback
        self.login_button.setEnabled(False)
        self.login_button.setText("Signing In...")
        
        # Get credentials
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        # Basic validation
        if not username:
            self.username_status.set_error("Please enter your username or email")
            self.login_button.setEnabled(True)
            self.login_button.setText("Sign In")
            return
        
        if not password:
            self.password_status.set_error("Please enter your password")
            self.login_button.setEnabled(True)
            self.login_button.setText("Sign In")
            return
        
        # Small delay to simulate network communication
        QTimer.singleShot(400, lambda: self._perform_login(username, password))
    
    def _perform_login(self, username, password):
        """Perform actual login after animation"""
        # Attempt login
        try:
            success, user_id, username = self.user_manager.login(username, password)
            if success:
                self.form_status.set_success("Login successful")
                
                # Save credentials if remember me is checked
                if self.remember_checkbox.isChecked():
                    self.user_manager.save_remembered_credentials(self.username_input.text().strip())
                else:
                    self.user_manager.clear_remembered_credentials()
                
                # Emit signal with user info
                QTimer.singleShot(500, lambda: self.login_successful.emit(user_id, username))
            else:
                self.form_status.set_error("Invalid username/email or password")
                self.login_button.setEnabled(True)
                self.login_button.setText("Sign In")
                
                # Shake animation for failed login
                self._shake_effect(self.login_button)
        except Exception as e:
            self.form_status.set_error(f"Login failed: {str(e)}")
            self.login_button.setEnabled(True)
            self.login_button.setText("Sign In")
    
    def _shake_effect(self, widget):
        """Add a shake animation for error feedback"""
        animation = QPropertyAnimation(widget, b"pos")
        animation.setDuration(500)
        animation.setEasingCurve(QEasingCurve.OutElastic)
        
        pos = widget.pos()
        
        animation.setKeyValueAt(0, pos)
        animation.setKeyValueAt(0.1, pos + QPoint(5, 0))
        animation.setKeyValueAt(0.2, pos + QPoint(-5, 0))
        animation.setKeyValueAt(0.3, pos + QPoint(5, 0))
        animation.setKeyValueAt(0.4, pos + QPoint(-5, 0))
        animation.setKeyValueAt(0.5, pos + QPoint(5, 0))
        animation.setKeyValueAt(0.6, pos + QPoint(-5, 0))
        animation.setKeyValueAt(0.7, pos + QPoint(5, 0))
        animation.setKeyValueAt(0.8, pos + QPoint(-5, 0))
        animation.setKeyValueAt(0.9, pos + QPoint(5, 0))
        animation.setKeyValueAt(1, pos)
        
        animation.start()
    
    def on_register(self):
        """Switch to registration page"""
        self.show_register.emit()
    
    def on_forgot_password(self):
        """Switch to forgot password page"""
        self.show_forgot_password.emit()
    
    def on_remember_me_changed(self, state):
        """Handle remember me checkbox change"""
        if not state:  # If unchecked
            # Clear remembered credentials
            self.user_manager.clear_remembered_credentials()
    
    def clear_form(self):
        """Clear the login form"""
        self.username_input.clear()
        self.password_input.clear()
        self.username_status.clear()
        self.password_status.clear()
        self.form_status.clear()
        self.remember_checkbox.setChecked(False)
        self.login_button.setEnabled(True)
        self.login_button.setText("Sign In")
    
    def load_remembered_credentials(self):
        """Load remembered credentials if available"""
        success, username_or_email = self.user_manager.load_remembered_credentials()
        if success and username_or_email:
            self.username_input.setText(username_or_email)
            self.remember_checkbox.setChecked(True)
            # Set focus to password field for better UX
            QTimer.singleShot(100, lambda: self.password_input.setFocus()) 