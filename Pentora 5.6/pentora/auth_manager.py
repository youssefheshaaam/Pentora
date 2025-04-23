#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Pentora - Authentication Manager - Enhanced UI
# Copyright (C) 2025 Pentora Team

from PyQt5.QtWidgets import (
    QWidget, QStackedWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout,
    QFrame, QSizePolicy, QSpacerItem
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve, QPoint
from PyQt5.QtGui import QFont, QColor, QCursor, QPixmap

from .auth import UserManager
from .auth_ui import LoginWidget, COLORS, STYLE_SHEETS
from .auth_ui_register import RegistrationWidget
from .auth_ui_forgot import ForgotPasswordWidget

class AuthenticationManager(QWidget):
    """Main authentication flow manager widget with enhanced modern UI"""
    
    # Signals
    auth_successful = pyqtSignal(str, str)  # user_id, username
    auth_logout = pyqtSignal()
    
    def __init__(self, parent=None, data_path=None):
        super().__init__(parent)
        
        # Initialize user manager
        self.user_manager = UserManager(data_path)
        
        # Initialize fonts
        self.setup_fonts()
        
        # Initialize modern UI
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
        self.subtitle_font.setPointSize(13)
        
        self.button_font = QFont()
        self.button_font.setFamily("SF Pro Text")
        self.button_font.setPointSize(10)
        self.button_font.setBold(True)
    
    def init_ui(self):
        """Initialize the user interface with modern styling"""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create stacked widget for authentication flows
        self.auth_stack = QStackedWidget()
        
        # Create individual screens
        self.login_screen = LoginWidget(self.user_manager)
        self.register_screen = RegistrationWidget(self.user_manager)
        self.forgot_password_screen = ForgotPasswordWidget(self.user_manager)
        self.authenticated_screen = self.create_authenticated_screen()
        
        # Add screens to stack
        self.auth_stack.addWidget(self.login_screen)
        self.auth_stack.addWidget(self.register_screen)
        self.auth_stack.addWidget(self.forgot_password_screen)
        self.auth_stack.addWidget(self.authenticated_screen)
        
        # Connect signals
        self.login_screen.login_successful.connect(self.on_auth_successful)
        self.login_screen.show_register.connect(self.show_register)
        self.login_screen.show_forgot_password.connect(self.show_forgot_password)
        
        self.register_screen.registration_successful.connect(self.on_auth_successful)
        self.register_screen.show_login.connect(self.show_login)
        
        self.forgot_password_screen.show_login.connect(self.show_login)
        self.forgot_password_screen.password_reset_complete.connect(self.show_login)
        
        # Add stack to main layout
        main_layout.addWidget(self.auth_stack)
        
        # Set initial screen based on login status
        if self.user_manager.is_logged_in():
            self.show_authenticated()
        else:
            # Check if we have remembered credentials
            has_remembered, _ = self.user_manager.load_remembered_credentials()
            self.show_login()
    
    def create_authenticated_screen(self):
        """Create the authenticated user screen with modern design"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(25)
        
        # Create logo/icon (optional)
        logo_container = QWidget()
        logo_layout = QHBoxLayout(logo_container)
        logo_layout.setContentsMargins(0, 0, 0, 15)
        
        logo_label = QLabel()
        logo_label.setText("👤")  # User emoji as placeholder
        logo_label.setStyleSheet(f"font-size: 64px; color: {COLORS['primary']};")
        logo_label.setAlignment(Qt.AlignCenter)
        logo_layout.addWidget(logo_label)
        
        layout.addWidget(logo_container)
        
        # User info card with modern design
        user_card = QFrame()
        user_card.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS["surface"]};
                border-radius: 16px;
                border: 1px solid {COLORS["border"]};
            }}
        """)
        
        # User card layout with better spacing
        user_layout = QVBoxLayout(user_card)
        user_layout.setContentsMargins(30, 30, 30, 30)
        user_layout.setSpacing(20)
        
        # Welcome message with modern typography
        self.welcome_label = QLabel("Welcome!")
        self.welcome_label.setFont(self.title_font)
        self.welcome_label.setStyleSheet(f"color: {COLORS['primary']}; font-size: 28px;")
        self.welcome_label.setAlignment(Qt.AlignCenter)
        
        # User info with modern styling
        self.user_info_label = QLabel()
        self.user_info_label.setFont(self.subtitle_font)
        self.user_info_label.setStyleSheet(f"color: {COLORS['text_secondary']};")
        self.user_info_label.setAlignment(Qt.AlignCenter)
        
        # Message below user info
        success_message = QLabel("You have successfully authenticated!")
        success_message.setStyleSheet(f"color: {COLORS['success']}; font-size: 14px;")
        success_message.setAlignment(Qt.AlignCenter)
        
        # Separator with gradient styling
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setStyleSheet(f"""
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                stop:0 {COLORS["primary"]}00, 
                stop:0.5 {COLORS["primary"]}60, 
                stop:1 {COLORS["primary"]}00);
            min-height: 1px;
            border: none;
        """)
        
        # Add some space
        spacer = QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding)
        
        # Action buttons container
        button_container = QWidget()
        button_layout = QVBoxLayout(button_container)
        button_layout.setContentsMargins(20, 10, 20, 10)
        button_layout.setSpacing(15)
        
        # Start using app button
        start_button = QPushButton("Continue to Application")
        start_button.setFont(self.button_font)
        start_button.setStyleSheet(STYLE_SHEETS["primary_button"])
        start_button.setCursor(QCursor(Qt.PointingHandCursor))
        start_button.setMinimumHeight(48)
        
        # Logout button with modern styling
        self.logout_button = QPushButton("Sign Out")
        self.logout_button.setFont(self.button_font)
        self.logout_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS["surface"]};
                color: {COLORS["danger"]};
                border: 1px solid {COLORS["danger"]};
                border-radius: 6px;
                padding: 10px 16px;
                font-size: 13px;
                min-height: 20px;
            }}
            QPushButton:hover {{
                background-color: {COLORS["danger"]}10;
            }}
            QPushButton:pressed {{
                background-color: {COLORS["danger"]}20;
            }}
        """)
        self.logout_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.logout_button.clicked.connect(self.on_logout)
        self.logout_button.setMinimumHeight(48)
        
        # Add buttons to layout
        button_layout.addWidget(start_button)
        button_layout.addWidget(self.logout_button)
        
        # Add all elements to user card
        user_layout.addWidget(self.welcome_label)
        user_layout.addWidget(self.user_info_label)
        user_layout.addWidget(success_message)
        user_layout.addWidget(separator)
        user_layout.addItem(spacer)
        user_layout.addWidget(button_container)
        
        # Add card to main layout
        layout.addWidget(user_card)
        layout.addStretch()
        
        return widget
    
    def show_login(self):
        """Show the login screen with transition animation"""
        # Prepare animation
        self.auth_stack.setCurrentWidget(self.login_screen)
        
        # Clear form
        self.login_screen.clear_form()
    
    def show_register(self):
        """Show the registration screen with transition animation"""
        # Prepare animation
        self.auth_stack.setCurrentWidget(self.register_screen)
        
        # Clear form
        self.register_screen.clear_form()
    
    def show_forgot_password(self):
        """Show the forgot password screen with transition animation"""
        # Prepare animation
        self.auth_stack.setCurrentWidget(self.forgot_password_screen)
        
        # Clear form
        self.forgot_password_screen.clear_form()
    
    def show_authenticated(self):
        """Show the authenticated user screen with transition"""
        if self.user_manager.is_logged_in():
            # Get user data
            user = self.user_manager.get_current_user()
            
            # Update welcome message with name and modern formatting
            self.welcome_label.setText(f"Welcome, {user['username']}!")
            
            # Update user info
            self.user_info_label.setText(f"Signed in as {user['email']}")
            
            # Set current widget
            self.auth_stack.setCurrentWidget(self.authenticated_screen)
    
    def on_auth_successful(self, user_id, username):
        """Handle successful authentication with animation"""
        # Add success animation
        QTimer.singleShot(300, lambda: self.show_authenticated())
        
        # Emit signal
        self.auth_successful.emit(user_id, username)
    
    def on_logout(self):
        """Handle logout with animation"""
        # Log out user
        self.user_manager.logout()
        
        # Show transition after short delay
        QTimer.singleShot(300, lambda: self.show_login())
        
        # Emit signal
        self.auth_logout.emit()
    
    def get_user_manager(self):
        """Get the user manager instance"""
        return self.user_manager
    
    def is_authenticated(self):
        """Check if a user is authenticated"""
        return self.user_manager.is_logged_in()
    
    def get_current_user(self):
        """Get the current user"""
        return self.user_manager.get_current_user() 