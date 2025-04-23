#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Pentora - Registration UI components - Enhanced UI
# Copyright (C) 2025 Pentora Team

from PyQt5.QtWidgets import (
    QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, 
    QFormLayout, QFrame, QCheckBox, QSpacerItem, QSizePolicy, QMessageBox
)
from PyQt5.QtCore import Qt, pyqtSignal, QRegExp, QTimer, QPropertyAnimation, QEasingCurve, QPoint
from PyQt5.QtGui import QRegExpValidator, QIcon, QColor, QCursor, QFont

from .auth import UserManager, ValidationError
from .auth_ui import FormStatusLabel, PasswordStrengthWidget, COLORS, STYLE_SHEETS, apply_shadow

class RegistrationWidget(QWidget):
    """Registration screen widget with enhanced modern UI"""
    
    # Signals
    registration_successful = pyqtSignal(str, str)  # user_id, username
    show_login = pyqtSignal()
    
    def __init__(self, user_manager, parent=None):
        super().__init__(parent)
        self.user_manager = user_manager
        
        # Initialize fonts
        self.setup_fonts()
        
        # Initialize the modernized UI
        self.init_ui()
    
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
    
    def init_ui(self):
        """Initialize the user interface with modern styling"""
        # Main layout with better spacing
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.setSpacing(20)
        
        # Create logo/icon (optional)
        logo_container = QWidget()
        logo_layout = QHBoxLayout(logo_container)
        logo_layout.setContentsMargins(0, 0, 0, 15)
        
        logo_label = QLabel()
        logo_label.setText("✨")  # Sparkle emoji as placeholder, replace with actual logo
        logo_label.setStyleSheet("font-size: 42px; color: #6C63FF;")
        logo_label.setAlignment(Qt.AlignCenter)
        logo_layout.addWidget(logo_label)
        
        main_layout.addWidget(logo_container)
        
        # Title with modern font and styling
        title_label = QLabel("Create Account")
        title_label.setFont(self.title_font)
        title_label.setStyleSheet(STYLE_SHEETS["title_label"])
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("Join us today and get started")
        subtitle_label.setFont(self.subtitle_font)
        subtitle_label.setStyleSheet(STYLE_SHEETS["subtitle_label"])
        subtitle_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(subtitle_label)
        
        # Form frame with shadow effect
        form_frame = QFrame()
        form_frame.setStyleSheet(STYLE_SHEETS["container_frame"])
        form_layout = QVBoxLayout(form_frame)
        form_layout.setContentsMargins(25, 25, 25, 25)
        form_layout.setSpacing(15)  # Slightly reduced spacing
        
        # Apply shadow effect to form
        apply_shadow(form_frame)
        
        # Use a grid layout for the form to ensure better alignment
        form_grid = QFormLayout()
        form_grid.setSpacing(10)  # Reduce spacing between form elements
        form_grid.setContentsMargins(0, 0, 0, 0)
        form_grid.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        
        # Username field with better layout and styling
        username_label = QLabel("Username")
        username_label.setStyleSheet(STYLE_SHEETS["field_label"])
        
        username_container = QWidget()
        username_container_layout = QVBoxLayout(username_container)
        username_container_layout.setContentsMargins(0, 0, 0, 0)
        username_container_layout.setSpacing(2)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Choose a username")
        self.username_input.setStyleSheet(STYLE_SHEETS["line_edit"])
        self.username_input.setCursor(QCursor(Qt.IBeamCursor))
        
        self.username_status = FormStatusLabel()
        
        username_container_layout.addWidget(self.username_input)
        username_container_layout.addWidget(self.username_status)
        
        # Email field with better layout and styling
        email_label = QLabel("Email")
        email_label.setStyleSheet(STYLE_SHEETS["field_label"])
        
        email_container = QWidget()
        email_container_layout = QVBoxLayout(email_container)
        email_container_layout.setContentsMargins(0, 0, 0, 0)
        email_container_layout.setSpacing(2)
        
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter your email address")
        self.email_input.setStyleSheet(STYLE_SHEETS["line_edit"])
        self.email_input.setCursor(QCursor(Qt.IBeamCursor))
        
        # Set up email validator with modern error handling
        email_regex = QRegExp(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        email_validator = QRegExpValidator(email_regex)
        self.email_input.setValidator(email_validator)
        
        self.email_status = FormStatusLabel()
        
        email_container_layout.addWidget(self.email_input)
        email_container_layout.addWidget(self.email_status)
        
        # Password field with better layout and styling
        password_label = QLabel("Password")
        password_label.setStyleSheet(STYLE_SHEETS["field_label"])
        
        password_container = QWidget()
        password_container_layout = QVBoxLayout(password_container)
        password_container_layout.setContentsMargins(0, 0, 0, 0)
        password_container_layout.setSpacing(2)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Create a strong password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet(STYLE_SHEETS["line_edit"])
        self.password_input.setCursor(QCursor(Qt.IBeamCursor))
        
        self.password_status = FormStatusLabel()
        
        # Password strength meter - simplified
        self.password_strength = PasswordStrengthWidget()
        
        password_container_layout.addWidget(self.password_input)
        password_container_layout.addWidget(self.password_status)
        password_container_layout.addWidget(self.password_strength)
        
        # Confirm Password field
        confirm_label = QLabel("Confirm Password")
        confirm_label.setStyleSheet(STYLE_SHEETS["field_label"])
        
        confirm_container = QWidget()
        confirm_container_layout = QVBoxLayout(confirm_container)
        confirm_container_layout.setContentsMargins(0, 0, 0, 0)
        confirm_container_layout.setSpacing(2)
        
        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("Confirm your password")
        self.confirm_input.setEchoMode(QLineEdit.Password)
        self.confirm_input.setStyleSheet(STYLE_SHEETS["line_edit"])
        self.confirm_input.setCursor(QCursor(Qt.IBeamCursor))
        
        self.confirm_status = FormStatusLabel()
        
        confirm_container_layout.addWidget(self.confirm_input)
        confirm_container_layout.addWidget(self.confirm_status)
        
        # Add fields to form grid
        form_grid.addRow(username_label, username_container)
        form_grid.addRow(email_label, email_container)
        form_grid.addRow(password_label, password_container)
        form_grid.addRow(confirm_label, confirm_container)
        
        # Add form grid to main form layout
        form_layout.addLayout(form_grid)
        
        # Form status - centralized error/success messages
        self.form_status = FormStatusLabel()
        self.form_status.setAlignment(Qt.AlignCenter)
        form_layout.addWidget(self.form_status)
        
        # Terms and conditions checkbox with modern styling
        terms_layout = QHBoxLayout()
        terms_layout.setContentsMargins(0, 5, 0, 5)
        
        self.terms_checkbox = QCheckBox("I agree to the Terms and Privacy Policy")
        self.terms_checkbox.setStyleSheet(STYLE_SHEETS["checkbox"])
        self.terms_checkbox.setCursor(QCursor(Qt.PointingHandCursor))
        
        terms_layout.addWidget(self.terms_checkbox)
        form_layout.addLayout(terms_layout)
        
        # Register button with modern styling and hover effects
        self.register_button = QPushButton("Create Account")
        self.register_button.setFont(self.button_font)
        self.register_button.setStyleSheet(STYLE_SHEETS["primary_button"])
        self.register_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.register_button.clicked.connect(self.on_register)
        self.register_button.setMinimumHeight(48)
        
        # Add subtle shadow to button
        apply_shadow(self.register_button, radius=10, y_offset=2)
        form_layout.addWidget(self.register_button)
        
        # Login link with modern styling
        login_layout = QHBoxLayout()
        login_label = QLabel("Already have an account?")
        login_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        
        login_button = QPushButton("Sign In")
        login_button.setStyleSheet(STYLE_SHEETS["text_button"])
        login_button.setCursor(QCursor(Qt.PointingHandCursor))
        login_button.clicked.connect(self.on_login)
        
        login_layout.addStretch()
        login_layout.addWidget(login_label)
        login_layout.addWidget(login_button)
        login_layout.addStretch()
        
        form_layout.addSpacing(5)  # Less spacing
        form_layout.addLayout(login_layout)
        
        # Add form to main layout
        main_layout.addWidget(form_frame)
        main_layout.addStretch()
        
        # Connect events
        self.username_input.textChanged.connect(self.on_username_changed)
        self.email_input.textChanged.connect(self.on_email_changed)
        self.password_input.textChanged.connect(self.on_password_changed)
        self.confirm_input.textChanged.connect(self.on_confirm_changed)
        self.terms_checkbox.stateChanged.connect(self.on_terms_changed)
        
        # Set tab order for better keyboard navigation
        self.setTabOrder(self.username_input, self.email_input)
        self.setTabOrder(self.email_input, self.password_input)
        self.setTabOrder(self.password_input, self.confirm_input)
        self.setTabOrder(self.confirm_input, self.terms_checkbox)
        self.setTabOrder(self.terms_checkbox, self.register_button)
    
    def on_username_changed(self, text):
        """Handle username field change with live validation"""
        self.username_status.clear()
        self.form_status.clear()
        
        # Only validate if there's input to avoid premature errors
        if len(text) > 0:
            # Validate username (basic check - more complex validation in auth.py)
            if len(text) < 3:
                self.username_status.set_error("Username must be at least 3 characters")
                return
            
            # Check for spaces
            if ' ' in text:
                self.username_status.set_error("Username cannot contain spaces")
                return
            
            # Show success indicator for valid format
            self.username_status.set_success("Valid username format")
            
            # Validate if username is available (throttled to avoid too many queries)
            QTimer.singleShot(800, lambda: self._check_username_availability(text))
    
    def _check_username_availability(self, username):
        """Check username availability if still the same value"""
        if username != self.username_input.text():
            return
        
        try:
            # Check if username is taken
            if self.user_manager.is_username_taken(username):
                self.username_status.set_error("Username already taken")
            else:
                self.username_status.set_success("Username available")
        except Exception as e:
            self.username_status.set_error(f"Error checking username: {str(e)}")
    
    def on_email_changed(self, text):
        """Handle email field change with live validation"""
        self.email_status.clear()
        self.form_status.clear()
        
        # Only validate if there's input to avoid premature errors
        if len(text) > 0:
            # Validate email format (basic check)
            if '@' not in text or '.' not in text:
                self.email_status.set_error("Please enter a valid email address")
                return
            
            # Show success indicator for valid format
            self.email_status.set_success("Valid email format")
            
            # Throttled check if email is already registered
            QTimer.singleShot(800, lambda: self._check_email_availability(text))
    
    def _check_email_availability(self, email):
        """Check email availability if still the same value"""
        if email != self.email_input.text():
            return
        
        try:
            # Check if email is taken
            if self.user_manager.is_email_taken(email):
                self.email_status.set_error("Email already registered")
            else:
                self.email_status.set_success("Email available")
        except Exception as e:
            self.email_status.set_error(f"Error checking email: {str(e)}")
    
    def on_password_changed(self, text):
        """Handle password field change with live validation"""
        self.password_status.clear()
        self.confirm_status.clear()
        self.form_status.clear()
        
        # Update password strength indicator
        self.password_strength.update_strength(text)
        
        # Only validate if there's input to avoid premature errors
        if len(text) > 0:
            # Validate password strength
            if len(text) < 8:
                self.password_status.set_error("Password must be at least 8 characters")
                return
            
            # Check password complexity
            has_upper = any(c.isupper() for c in text)
            has_lower = any(c.islower() for c in text)
            has_digit = any(c.isdigit() for c in text)
            
            if not (has_upper and has_lower and has_digit):
                self.password_status.set_error("Password must include uppercase, lowercase, and numbers")
                return
            
            # Show success indicator for strong password
            self.password_status.set_success("Strong password")
        
        # Check if confirm password still matches
        if self.confirm_input.text():
            self.on_confirm_changed(self.confirm_input.text())
    
    def on_confirm_changed(self, text):
        """Handle confirm password field change with live validation"""
        self.confirm_status.clear()
        self.form_status.clear()
        
        # Check if passwords match
        if self.password_input.text() != text:
            self.confirm_status.set_error("Passwords do not match")
        elif text:
            self.confirm_status.set_success("Passwords match")
    
    def on_terms_changed(self, state):
        """Handle terms checkbox change"""
        self.form_status.clear()
    
    def on_register(self):
        """Attempt to register user with enhanced feedback"""
        # Add animation to button for feedback
        self.register_button.setEnabled(False)
        self.register_button.setText("Creating Account...")
        
        # Get form data
        username = self.username_input.text().strip()
        email = self.email_input.text().strip()
        password = self.password_input.text()
        confirm = self.confirm_input.text()
        
        # Validate fields
        if not username:
            self.username_status.set_error("Please enter a username")
            self._reset_button()
            return
        
        if not email:
            self.email_status.set_error("Please enter your email address")
            self._reset_button()
            return
        
        if not password:
            self.password_status.set_error("Please create a password")
            self._reset_button()
            return
        
        if not confirm:
            self.confirm_status.set_error("Please confirm your password")
            self._reset_button()
            return
        
        if password != confirm:
            self.confirm_status.set_error("Passwords do not match")
            self._reset_button()
            return
        
        if not self.terms_checkbox.isChecked():
            self.form_status.set_error("You must agree to the Terms and Privacy Policy")
            self._reset_button()
            return
        
        # Small delay to simulate network communication
        QTimer.singleShot(500, lambda: self._perform_registration(username, email, password))
    
    def _perform_registration(self, username, email, password):
        """Perform the actual registration after animation"""
        try:
            user_id = self.user_manager.register_user(username, email, password)
            if user_id:
                self.form_status.set_success("Registration successful")
                
                # Emit signal with user info after a brief delay
                QTimer.singleShot(800, lambda: self.registration_successful.emit(user_id, username))
            else:
                self.form_status.set_error("Registration failed - Please try again")
                self._reset_button()
        except ValidationError as e:
            self.form_status.set_error(f"Validation error: {str(e)}")
            self._reset_button()
        except Exception as e:
            self.form_status.set_error(f"Registration failed: {str(e)}")
            self._reset_button()
    
    def _reset_button(self):
        """Reset the register button to enable state"""
        self.register_button.setEnabled(True)
        self.register_button.setText("Create Account")
        
        # Add shake animation for error feedback
        self._shake_effect(self.register_button)
    
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
    
    def on_login(self):
        """Switch to login page"""
        self.show_login.emit()
    
    def clear_form(self):
        """Clear the registration form"""
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
        self.register_button.setEnabled(True)
        self.register_button.setText("Create Account")
        self.password_strength.update_strength("") 