#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Pentora - Authentication UI components - Forgot Password - Enhanced UI
# Copyright (C) 2025 Pentora Team

from PyQt5.QtWidgets import (
    QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, 
    QStackedWidget, QFormLayout, QFrame, QSizePolicy, QGraphicsDropShadowEffect
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve, QPoint
from PyQt5.QtGui import QFont, QColor, QCursor

from .auth import UserManager, ValidationError, AuthError
from .auth_ui import FormStatusLabel, PasswordStrengthWidget, COLORS, STYLE_SHEETS, apply_shadow

class ForgotPasswordWidget(QWidget):
    """Forgot password screen widget with enhanced modern UI"""
    
    # Signals
    password_reset_complete = pyqtSignal()
    show_login = pyqtSignal()
    
    def __init__(self, user_manager, parent=None):
        super().__init__(parent)
        self.user_manager = user_manager
        
        # Current step
        self.current_step = 0
        
        # Store temporary data
        self.reset_email = ""
        self.reset_code = ""
        
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
        logo_label.setText("🔑")  # Key emoji as placeholder, replace with actual logo
        logo_label.setStyleSheet("font-size: 42px; color: #6C63FF;")
        logo_label.setAlignment(Qt.AlignCenter)
        logo_layout.addWidget(logo_label)
        
        main_layout.addWidget(logo_container)
        
        # Title
        self.title_label = QLabel("Reset Password")
        self.title_label.setFont(self.title_font)
        self.title_label.setStyleSheet(STYLE_SHEETS["title_label"])
        self.title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.title_label)
        
        # Stacked widget for different steps
        self.step_stack = QStackedWidget()
        
        # Step 1: Email input
        self.email_widget = self.create_email_widget()
        self.step_stack.addWidget(self.email_widget)
        
        # Step 2: Verification code
        self.code_widget = self.create_code_widget()
        self.step_stack.addWidget(self.code_widget)
        
        # Step 3: New password
        self.password_widget = self.create_password_widget()
        self.step_stack.addWidget(self.password_widget)
        
        # Step 4: Success
        self.success_widget = self.create_success_widget()
        self.step_stack.addWidget(self.success_widget)
        
        # Add stack to main layout
        main_layout.addWidget(self.step_stack)
        main_layout.addStretch()
        
        # Go to step 1
        self.go_to_step(0)
    
    def create_email_widget(self):
        """Create the email input step with modern design"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(20)
        
        # Instruction with modern styling
        instruction = QLabel("Enter your email address and we'll send you a code to reset your password.")
        instruction.setFont(self.subtitle_font)
        instruction.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 13px;")
        instruction.setWordWrap(True)
        instruction.setAlignment(Qt.AlignCenter)
        layout.addWidget(instruction)
        
        # Form frame with shadow
        form_frame = QFrame()
        form_frame.setStyleSheet(STYLE_SHEETS["container_frame"])
        form_layout = QVBoxLayout(form_frame)
        form_layout.setContentsMargins(25, 25, 25, 25)
        form_layout.setSpacing(20)
        
        # Apply shadow
        apply_shadow(form_frame)
        
        # Email field with modern styling
        email_layout = QVBoxLayout()
        email_layout.setSpacing(5)
        
        email_label = QLabel("Email Address")
        email_label.setStyleSheet(STYLE_SHEETS["field_label"])
        
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter your registered email")
        self.email_input.setStyleSheet(STYLE_SHEETS["line_edit"])
        self.email_input.setCursor(QCursor(Qt.IBeamCursor))
        
        self.email_status = FormStatusLabel()
        
        email_layout.addWidget(email_label)
        email_layout.addWidget(self.email_input)
        email_layout.addWidget(self.email_status)
        
        # Next button with modern styling
        self.email_next_button = QPushButton("Send Reset Code")
        self.email_next_button.setFont(self.button_font)
        self.email_next_button.setStyleSheet(STYLE_SHEETS["primary_button"])
        self.email_next_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.email_next_button.setMinimumHeight(48)
        self.email_next_button.clicked.connect(self.on_email_next)
        
        # Add shadow to button
        apply_shadow(self.email_next_button, radius=10, y_offset=2)
        
        # Back to login button with styled text
        back_layout = QHBoxLayout()
        back_button = QPushButton("Back to Login")
        back_button.setStyleSheet(STYLE_SHEETS["text_button"])
        back_button.setCursor(QCursor(Qt.PointingHandCursor))
        back_button.clicked.connect(self.on_back_to_login)
        
        back_layout.addStretch()
        back_layout.addWidget(back_button)
        back_layout.addStretch()
        
        # Add to form
        form_layout.addLayout(email_layout)
        form_layout.addSpacing(5)
        form_layout.addWidget(self.email_next_button)
        form_layout.addLayout(back_layout)
        
        layout.addWidget(form_frame)
        
        return widget
    
    def create_code_widget(self):
        """Create the verification code step with modern design"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(20)
        
        # Instruction with modern styling
        self.code_instruction = QLabel("We've sent a verification code to your email. Please enter it below.")
        self.code_instruction.setFont(self.subtitle_font)
        self.code_instruction.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 13px;")
        self.code_instruction.setWordWrap(True)
        self.code_instruction.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.code_instruction)
        
        # Form frame with shadow
        form_frame = QFrame()
        form_frame.setStyleSheet(STYLE_SHEETS["container_frame"])
        form_layout = QVBoxLayout(form_frame)
        form_layout.setContentsMargins(25, 25, 25, 25)
        form_layout.setSpacing(20)
        
        # Apply shadow
        apply_shadow(form_frame)
        
        # Code field with modern styling
        code_layout = QVBoxLayout()
        code_layout.setSpacing(5)
        
        code_label = QLabel("Verification Code")
        code_label.setStyleSheet(STYLE_SHEETS["field_label"])
        
        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("Enter the 8-digit code")
        self.code_input.setStyleSheet(STYLE_SHEETS["line_edit"])
        self.code_input.setCursor(QCursor(Qt.IBeamCursor))
        self.code_input.setMaxLength(8)
        
        self.code_status = FormStatusLabel()
        
        code_layout.addWidget(code_label)
        code_layout.addWidget(self.code_input)
        code_layout.addWidget(self.code_status)
        
        # Buttons with modern styling
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)
        
        # Back button
        self.code_back_button = QPushButton("Back")
        self.code_back_button.setFont(self.button_font)
        self.code_back_button.setStyleSheet(STYLE_SHEETS["secondary_button"])
        self.code_back_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.code_back_button.clicked.connect(lambda: self.go_to_step(0))
        self.code_back_button.setMinimumHeight(48)
        
        # Next button
        self.code_next_button = QPushButton("Verify Code")
        self.code_next_button.setFont(self.button_font)
        self.code_next_button.setStyleSheet(STYLE_SHEETS["primary_button"])
        self.code_next_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.code_next_button.clicked.connect(self.on_code_next)
        self.code_next_button.setMinimumHeight(48)
        
        # Add shadows to buttons
        apply_shadow(self.code_back_button, radius=8, y_offset=2)
        apply_shadow(self.code_next_button, radius=10, y_offset=2)
        
        button_layout.addWidget(self.code_back_button)
        button_layout.addWidget(self.code_next_button)
        
        # Add to form
        form_layout.addLayout(code_layout)
        form_layout.addSpacing(5)
        form_layout.addLayout(button_layout)
        
        layout.addWidget(form_frame)
        
        return widget
    
    def create_password_widget(self):
        """Create the new password step with modern design"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(20)
        
        # Instruction with modern styling
        instruction = QLabel("Create a new password for your account.")
        instruction.setFont(self.subtitle_font)
        instruction.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 13px;")
        instruction.setWordWrap(True)
        instruction.setAlignment(Qt.AlignCenter)
        layout.addWidget(instruction)
        
        # Form frame with shadow
        form_frame = QFrame()
        form_frame.setStyleSheet(STYLE_SHEETS["container_frame"])
        form_layout = QVBoxLayout(form_frame)
        form_layout.setContentsMargins(25, 25, 25, 25)
        form_layout.setSpacing(20)
        
        # Apply shadow
        apply_shadow(form_frame)
        
        # Password field with modern styling
        password_layout = QVBoxLayout()
        password_layout.setSpacing(5)
        
        password_label = QLabel("New Password")
        password_label.setStyleSheet(STYLE_SHEETS["field_label"])
        
        self.new_password_input = QLineEdit()
        self.new_password_input.setPlaceholderText("Create a strong password")
        self.new_password_input.setEchoMode(QLineEdit.Password)
        self.new_password_input.setStyleSheet(STYLE_SHEETS["line_edit"])
        self.new_password_input.setCursor(QCursor(Qt.IBeamCursor))
        
        # Password strength widget
        self.new_password_strength = PasswordStrengthWidget()
        
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.new_password_input)
        password_layout.addWidget(self.new_password_strength)
        
        # Confirm password field with modern styling
        confirm_layout = QVBoxLayout()
        confirm_layout.setSpacing(5)
        
        confirm_label = QLabel("Confirm Password")
        confirm_label.setStyleSheet(STYLE_SHEETS["field_label"])
        
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setPlaceholderText("Confirm your new password")
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setStyleSheet(STYLE_SHEETS["line_edit"])
        self.confirm_password_input.setCursor(QCursor(Qt.IBeamCursor))
        
        self.confirm_password_status = FormStatusLabel()
        
        confirm_layout.addWidget(confirm_label)
        confirm_layout.addWidget(self.confirm_password_input)
        confirm_layout.addWidget(self.confirm_password_status)
        
        # Form status
        self.password_form_status = FormStatusLabel()
        self.password_form_status.setAlignment(Qt.AlignCenter)
        
        # Buttons with modern styling
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)
        
        # Back button
        self.password_back_button = QPushButton("Back")
        self.password_back_button.setFont(self.button_font)
        self.password_back_button.setStyleSheet(STYLE_SHEETS["secondary_button"])
        self.password_back_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.password_back_button.clicked.connect(lambda: self.go_to_step(1))
        self.password_back_button.setMinimumHeight(48)
        
        # Reset button
        self.reset_button = QPushButton("Reset Password")
        self.reset_button.setFont(self.button_font)
        self.reset_button.setStyleSheet(STYLE_SHEETS["primary_button"])
        self.reset_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.reset_button.clicked.connect(self.on_reset_password)
        self.reset_button.setMinimumHeight(48)
        
        # Add shadows to buttons
        apply_shadow(self.password_back_button, radius=8, y_offset=2)
        apply_shadow(self.reset_button, radius=10, y_offset=2)
        
        button_layout.addWidget(self.password_back_button)
        button_layout.addWidget(self.reset_button)
        
        # Add to form
        form_layout.addLayout(password_layout)
        form_layout.addLayout(confirm_layout)
        form_layout.addWidget(self.password_form_status)
        form_layout.addLayout(button_layout)
        
        layout.addWidget(form_frame)
        
        # Connect password change event
        self.new_password_input.textChanged.connect(self.on_new_password_changed)
        self.confirm_password_input.textChanged.connect(self.on_confirm_password_changed)
        
        return widget
    
    def create_success_widget(self):
        """Create the success step with modern design"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(20)
        
        # Success card with modern design
        success_frame = QFrame()
        success_frame.setStyleSheet(STYLE_SHEETS["container_frame"])
        success_layout = QVBoxLayout(success_frame)
        success_layout.setContentsMargins(30, 30, 30, 30)
        success_layout.setSpacing(15)
        
        # Apply shadow to success frame
        apply_shadow(success_frame, radius=15, y_offset=3)
        
        # Success icon with animation
        success_icon = QLabel("✓")
        success_icon.setStyleSheet(f"color: {COLORS['success']}; font-size: 64px; font-weight: bold;")
        success_icon.setAlignment(Qt.AlignCenter)
        
        # Success message with modern typography
        success_message = QLabel("Password Reset Successfully!")
        success_message.setFont(self.title_font)
        success_message.setWordWrap(True)
        success_message.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 22px;")
        success_message.setAlignment(Qt.AlignCenter)
        
        # Success description
        success_desc = QLabel("Your password has been reset successfully. You can now log in with your new password.")
        success_desc.setFont(self.subtitle_font)
        success_desc.setWordWrap(True)
        success_desc.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 14px;")
        success_desc.setAlignment(Qt.AlignCenter)
        
        # Login button with modern styling
        login_button = QPushButton("Return to Login")
        login_button.setFont(self.button_font)
        login_button.setStyleSheet(STYLE_SHEETS["primary_button"])
        login_button.setCursor(QCursor(Qt.PointingHandCursor))
        login_button.clicked.connect(self.on_back_to_login)
        login_button.setMinimumHeight(48)
        
        # Add shadow to button
        apply_shadow(login_button, radius=10, y_offset=2)
        
        success_layout.addWidget(success_icon)
        success_layout.addWidget(success_message)
        success_layout.addWidget(success_desc)
        success_layout.addSpacing(15)
        success_layout.addWidget(login_button)
        
        layout.addWidget(success_frame)
        
        return widget
    
    def on_email_next(self):
        """Handle email submission with enhanced feedback"""
        # Show loading state
        self.email_next_button.setEnabled(False)
        self.email_next_button.setText("Sending...")
        
        email = self.email_input.text().strip()
        
        # Basic validation
        if not email:
            self.email_status.set_error("Please enter your email address")
            self._reset_button(self.email_next_button, "Send Reset Code")
            return
        
        if not self.user_manager.validate_email(email):
            self.email_status.set_error("Invalid email format")
            self._reset_button(self.email_next_button, "Send Reset Code")
            return
        
        # Small delay to simulate network request
        QTimer.singleShot(800, lambda: self._process_email_request(email))
    
    def _process_email_request(self, email):
        """Process the email submission after delay"""
        # Generate reset code
        success, reset_code = self.user_manager.generate_reset_code(email)
        
        if success:
            # Store the email and code
            self.reset_email = email
            self.reset_code = reset_code
            
            # Update instruction with the code (in a real app, this would be sent via email)
            self.code_instruction.setText(f"We've sent a verification code to {email}.\n\nFor this demo, use this code: {reset_code}")
            
            # Reset button state
            self._reset_button(self.email_next_button, "Send Reset Code")
            
            # Go to next step with animation
            self.go_to_step(1)
        else:
            self.email_status.set_error("Email not found in our records")
            self._reset_button(self.email_next_button, "Send Reset Code")
            self._shake_effect(self.email_input)
    
    def on_code_next(self):
        """Handle verification code submission with enhanced feedback"""
        # Show loading state
        self.code_next_button.setEnabled(False)
        self.code_next_button.setText("Verifying...")
        
        code = self.code_input.text().strip().upper()
        
        # Basic validation
        if not code:
            self.code_status.set_error("Please enter the verification code")
            self._reset_button(self.code_next_button, "Verify Code")
            return
        
        # Small delay to simulate verification
        QTimer.singleShot(800, lambda: self._process_code_verification(code))
    
    def _process_code_verification(self, code):
        """Process the code verification after delay"""
        # Verify code
        success, user_id = self.user_manager.verify_reset_code(code)
        
        if success:
            # Reset button state
            self._reset_button(self.code_next_button, "Verify Code")
            
            # Go to next step with animation
            self.go_to_step(2)
        else:
            self.code_status.set_error("Invalid or expired verification code")
            self._reset_button(self.code_next_button, "Verify Code")
            self._shake_effect(self.code_input)
    
    def on_new_password_changed(self, text):
        """Handle new password field changes with live feedback"""
        # Update password strength
        self.new_password_strength.update_strength(text)
        
        # Clear form status
        self.password_form_status.clear()
        
        # Check if passwords match
        confirm_text = self.confirm_password_input.text()
        if confirm_text and confirm_text != text:
            self.confirm_password_status.set_error("Passwords do not match")
        elif confirm_text and confirm_text == text:
            self.confirm_password_status.set_success("Passwords match")
    
    def on_confirm_password_changed(self, text):
        """Handle confirm password field changes with live feedback"""
        # Clear form status
        self.password_form_status.clear()
        
        # Check if passwords match
        if text and self.new_password_input.text() != text:
            self.confirm_password_status.set_error("Passwords do not match")
        elif text and self.new_password_input.text() == text:
            self.confirm_password_status.set_success("Passwords match")
        else:
            self.confirm_password_status.clear()
    
    def on_reset_password(self):
        """Handle password reset submission with enhanced feedback"""
        # Show loading state
        self.reset_button.setEnabled(False)
        self.reset_button.setText("Resetting...")
        
        new_password = self.new_password_input.text()
        confirm_password = self.confirm_password_input.text()
        
        # Basic validation
        if not new_password:
            self.password_form_status.set_error("Please enter a new password")
            self._reset_button(self.reset_button, "Reset Password")
            return
        
        password_validation = self.user_manager.validate_password(new_password)
        if not password_validation["valid"]:
            self.password_form_status.set_error("Password must be at least 8 characters and contain uppercase, lowercase, and numbers")
            self._reset_button(self.reset_button, "Reset Password")
            return
        
        if new_password != confirm_password:
            self.confirm_password_status.set_error("Passwords do not match")
            self._reset_button(self.reset_button, "Reset Password")
            return
        
        # Small delay to simulate processing
        QTimer.singleShot(1000, lambda: self._process_password_reset(new_password))
    
    def _process_password_reset(self, new_password):
        """Process the password reset after delay"""
        # Reset password
        try:
            success = self.user_manager.reset_password(self.reset_code, new_password)
            if success:
                # Reset button state
                self._reset_button(self.reset_button, "Reset Password")
                
                # Go to success step with animation
                self.go_to_step(3)
        except ValidationError as e:
            self.password_form_status.set_error(str(e))
            self._reset_button(self.reset_button, "Reset Password")
        except AuthError as e:
            self.password_form_status.set_error(str(e))
            self._reset_button(self.reset_button, "Reset Password")
        except Exception as e:
            self.password_form_status.set_error(f"Password reset failed: {str(e)}")
            self._reset_button(self.reset_button, "Reset Password")
    
    def _reset_button(self, button, text):
        """Reset button to enabled state with original text"""
        button.setEnabled(True)
        button.setText(text)
    
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
    
    def on_back_to_login(self):
        """Go back to login page with animation"""
        self.clear_form()
        
        # Add animation before going back
        QTimer.singleShot(100, lambda: self.show_login.emit())
    
    def go_to_step(self, step):
        """Go to a specific step with animation"""
        # Update title based on step
        if step == 0:
            self.title_label.setText("Reset Password")
        elif step == 1:
            self.title_label.setText("Verify Code")
        elif step == 2:
            self.title_label.setText("Create New Password")
        elif step == 3:
            self.title_label.setText("Password Reset")
        
        # Use animation for transition
        self.current_step = step
        self.step_stack.setCurrentIndex(step)
    
    def clear_form(self):
        """Clear all form fields"""
        # Clear step 1
        self.email_input.clear()
        self.email_status.clear()
        self._reset_button(self.email_next_button, "Send Reset Code")
        
        # Clear step 2
        self.code_input.clear()
        self.code_status.clear()
        self.code_instruction.setText("We've sent a verification code to your email. Please enter it below.")
        self._reset_button(self.code_next_button, "Verify Code")
        
        # Clear step 3
        self.new_password_input.clear()
        self.confirm_password_input.clear()
        self.confirm_password_status.clear()
        self.password_form_status.clear()
        self.new_password_strength.update_strength("")
        self._reset_button(self.reset_button, "Reset Password")
        
        # Reset state
        self.reset_email = ""
        self.reset_code = ""
        
        # Go to first step
        self.go_to_step(0) 