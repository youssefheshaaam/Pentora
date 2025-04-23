#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Pentora - GUI-based vulnerability scanner with authentication
# Copyright (C) 2025 Pentora Team

import os
import sys
import json
import requests
import tempfile
from pathlib import Path
import html
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QStackedWidget, QMessageBox, QPushButton, QFrame,
    QLineEdit, QComboBox, QSpinBox, QTextEdit, QScrollArea, QDialog, QGridLayout,
    QFormLayout, QMenu
)
from PyQt5.QtCore import Qt, QSize, QPropertyAnimation, QEasingCurve, QPoint, QTimer, pyqtSignal
from PyQt5.QtGui import QPixmap, QIcon, QFont, QColor, QCursor, QPalette, QBrush, QLinearGradient, QFontDatabase, QIconEngine, QPainter

# Import auth components and design elements
from .auth_manager import AuthenticationManager
from .auth_ui import COLORS, STYLE_SHEETS

# Import main window for access to utility methods
from .pentora_gui import PentoraMainWindow, get_app_icon_path

class MaterialIcon:
    """Class to handle Material Icons from Google Fonts"""
    
    # Path to store the material icons
    ICON_FONT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources", "fonts")
    MATERIAL_ICONS_URL = "https://github.com/google/material-design-icons/raw/master/font/MaterialIcons-Regular.ttf"
    MATERIAL_ICONS_FONT_FAMILY = "Material Icons"
    
    @classmethod
    def initialize(cls):
        """Initialize Material Icons by ensuring the font is available"""
        os.makedirs(cls.ICON_FONT_PATH, exist_ok=True)
        
        font_path = os.path.join(cls.ICON_FONT_PATH, "MaterialIcons-Regular.ttf")
        
        # Check if font file exists
        if not os.path.exists(font_path):
            cls._download_material_icons(font_path)
        
        # Load the font
        font_id = QFontDatabase.addApplicationFont(font_path)
        if font_id == -1:
            print("Failed to load Material Icons font")
            return False
        
        return True
    
    @classmethod
    def _download_material_icons(cls, font_path):
        """Download Material Icons font file from GitHub"""
        try:
            response = requests.get(cls.MATERIAL_ICONS_URL, stream=True)
            response.raise_for_status()
            
            with open(font_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            print(f"Downloaded Material Icons font to {font_path}")
            return True
        except Exception as e:
            print(f"Failed to download Material Icons font: {e}")
            return False
    
    @classmethod
    def get_icon(cls, icon_name, size=24, color=None):
        """Get a QLabel with the specified Material Icon
        
        Args:
            icon_name: The name of the icon from Material Icons
            size: Size of the icon in pixels
            color: Color of the icon (if None, uses text_primary color)
            
        Returns:
            QLabel with the icon
        """
        if color is None:
            color = COLORS['text_primary']
            
        label = QLabel()
        font = QFont(cls.MATERIAL_ICONS_FONT_FAMILY)
        font.setPixelSize(size)
        label.setFont(font)
        label.setText(icon_name)
        label.setStyleSheet(f"color: {color}; background: transparent;")
        label.setAlignment(Qt.AlignCenter)
        return label
    
    @classmethod
    def get_qicon(cls, icon_name, size=24, color=None):
        """Get a QIcon with the specified Material Icon
        
        Args:
            icon_name: The name of the icon from Material Icons
            size: Size of the icon in pixels
            color: Color of the icon (if None, uses text_primary color)
            
        Returns:
            QIcon with the Material Icon
        """
        if color is None:
            color = COLORS['text_primary']
            
        icon = QIcon()
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.transparent)
        
        font = QFont(cls.MATERIAL_ICONS_FONT_FAMILY)
        font.setPixelSize(size)
        
        painter = QPainter(pixmap)
        painter.setFont(font)
        painter.setPen(QColor(color))
        painter.drawText(pixmap.rect(), Qt.AlignCenter, icon_name)
        painter.end()
        
        icon = QIcon(pixmap)
        return icon
    
    @staticmethod
    def icon_name_to_text(icon_name):
        """Convert icon name to the actual character used in the font
        
        For Material Icons, the icon name is the same as the ligature text.
        
        Args:
            icon_name: Name of the icon
            
        Returns:
            Text to use with the Material Icons font
        """
        return icon_name

class ModernTabWidget(QTabWidget):
    """Enhanced tab widget with modern styling and animations"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTabPosition(QTabWidget.North)
        self.setDocumentMode(True)
        self.setMovable(True)
        self.setTabsClosable(False)
        
        # Dictionary mapping tab titles to appropriate Material Icons
        self.tab_icons = {
            "Dashboard": "dashboard",
            "Scan": "security",
            "Results": "assessment",
            "Reports": "description",
            "Network": "wifi",
            "Settings": "settings",
            "Help": "help",
            "About": "info"
        }
        
        # Modern styling
        self.setStyleSheet(f"""
            QTabWidget::pane {{
                border: none;
                background-color: {COLORS["surface"]};
                border-radius: 8px;
                margin-top: 4px;
            }}
            
            QTabBar::tab {{
                background-color: transparent;
                color: {COLORS["text_secondary"]};
                padding: 10px 16px;
                margin-right: 4px;
                min-width: 90px;
                font-size: 13px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                border: none;
            }}
            
            QTabBar::tab:selected {{
                color: {COLORS["primary"]};
                background-color: {COLORS["surface"]};
                font-weight: bold;
                border-bottom: 3px solid {COLORS["primary"]};
            }}
            
            QTabBar::tab:hover:!selected {{
                color: {COLORS["text_primary"]};
                background-color: rgba(255, 255, 255, 0.05);
            }}
            
            QTabBar {{
                border: none;
                background-color: transparent;
            }}
        """)
    
    def addTab(self, widget, title):
        """Override addTab to add Material Icons based on tab title"""
        icon = None
        if title in self.tab_icons:
            icon = MaterialIcon.get_qicon(self.tab_icons[title], size=20)
            return super().addTab(widget, icon, title)
        else:
            return super().addTab(widget, title)

class PentoraAuthApp(QMainWindow):
    """Main window for Pentora with authentication and modern UI"""
    
    def __init__(self):
        super().__init__()
        
        # Initialize modern UI
        self.init_ui()
        
        # Create auth manager
        self.auth_manager = AuthenticationManager()
        self.auth_manager.auth_successful.connect(self.on_auth_successful)
        self.auth_manager.auth_logout.connect(self.on_auth_logout)
        
        # Create main content (we'll show this after authentication)
        self.main_content = self.create_main_content()
        
        # Add pages to stack
        self.content_stack.addWidget(self.auth_manager)
        self.content_stack.addWidget(self.main_content)
        
        # Add animated transition effect to stack
        self.content_stack.setStyleSheet(f"""
            QStackedWidget {{
                background: {COLORS["background"]};
                border: none;
            }}
        """)
        
        # Show the appropriate screen based on auth status
        if self.auth_manager.is_authenticated():
            self.show_main_content()
        else:
            self.show_auth_screen()
    
    def init_ui(self):
        """Initialize the user interface with modern design"""
        # Set window properties
        self.setWindowTitle("Pentora - Vulnerability Scanner")
        self.resize(1280, 800)
        self.setMinimumSize(900, 600)
        
        # Set modern application style using COLORS from auth_ui
        self.setStyleSheet(f"""
            QMainWindow, QDialog {{
                background-color: {COLORS["background"]};
                color: {COLORS["text_primary"]};
                font-family: 'SF Pro Display', 'Helvetica Neue', 'Arial';
            }}
            
            QLabel {{
                color: {COLORS["text_primary"]};
                font-family: 'SF Pro Display', 'Helvetica Neue', 'Arial';
            }}
            
            QLineEdit, QComboBox, QSpinBox {{
                background-color: {COLORS["surface"]};
                color: {COLORS["text_primary"]};
                border: 1px solid {COLORS["border"]};
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 13px;
                selection-background-color: {COLORS["primary"]}50;
            }}
            
            QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{
                border: 2px solid {COLORS["primary"]};
            }}
            
            QLineEdit:hover:!focus, QComboBox:hover:!focus, QSpinBox:hover:!focus {{
                border: 1px solid {COLORS["primary"]}80;
            }}
            
            QComboBox::drop-down {{
                subcontrol-origin: padding;
                subcontrol-position: center right;
                width: 24px;
                border: none;
            }}
            
            QComboBox::down-arrow {{
                width: 14px;
                height: 14px;
            }}
            
            QComboBox QAbstractItemView {{
                background-color: {COLORS["surface"]};
                color: {COLORS["text_primary"]};
                border: 1px solid {COLORS["border"]};
                border-radius: 6px;
                padding: 4px;
                selection-background-color: {COLORS["primary"]}40;
                selection-color: {COLORS["text_primary"]};
            }}
            
            QTextEdit {{
                background-color: {COLORS["surface"]};
                color: {COLORS["text_primary"]};
                border: 1px solid {COLORS["border"]};
                border-radius: 6px;
                padding: 8px;
                font-family: 'Menlo', 'Monaco', monospace;
                font-size: 13px;
                selection-background-color: {COLORS["primary"]}50;
            }}
            
            QPushButton {{
                background-color: {COLORS["surface"]};
                color: {COLORS["text_primary"]};
                border: 1px solid {COLORS["border"]};
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 13px;
                min-height: 20px;
            }}
            
            QPushButton:hover {{
                background-color: #3A3A3A;
                border: 1px solid {COLORS["primary"]}50;
            }}
            
            QPushButton:pressed {{
                background-color: #202020;
            }}
            
            QPushButton#primary {{
                background-color: {COLORS["primary"]};
                color: {COLORS["text_light"]};
                border: none;
                font-weight: bold;
            }}
            
            QPushButton#primary:hover {{
                background-color: {COLORS["primary_hover"]};
            }}
            
            QPushButton#primary:pressed {{
                background-color: {COLORS["primary_active"]};
            }}
            
            QPushButton#secondary {{
                background-color: {COLORS["surface"]};
                color: {COLORS["primary"]};
                border: 1px solid {COLORS["primary"]};
            }}
            
            QPushButton#secondary:hover {{
                background-color: {COLORS["primary"]}10;
            }}
            
            QPushButton#secondary:pressed {{
                background-color: {COLORS["primary"]}20;
            }}
            
            QPushButton#danger {{
                background-color: {COLORS["danger"]};
                color: {COLORS["text_light"]};
                font-weight: bold;
                border: none;
            }}
            
            QPushButton#danger:hover {{
                background-color: #E05252;
            }}
            
            QPushButton#danger:pressed {{
                background-color: #C74545;
            }}
            
            QGroupBox {{
                background-color: {COLORS["surface"]};
                border: 1px solid {COLORS["border"]};
                border-radius: 8px;
                margin-top: 16px;
                padding: 15px;
                font-weight: bold;
            }}
            
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                top: -10px;
                padding: 0 5px;
                color: {COLORS["primary"]};
                background-color: {COLORS["surface"]};
            }}
            
            QScrollBar:vertical {{
                border: none;
                background: {COLORS["surface"]};
                width: 12px;
                margin: 0px;
                border-radius: 6px;
            }}
            
            QScrollBar::handle:vertical {{
                background: {COLORS["border"]};
                min-height: 20px;
                border-radius: 6px;
            }}
            
            QScrollBar::handle:vertical:hover {{
                background: #AAAAAA;
            }}
            
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                border: none;
                background: none;
                height: 0px;
            }}
            
            QScrollBar:horizontal {{
                border: none;
                background: {COLORS["surface"]};
                height: 12px;
                margin: 0px;
                border-radius: 6px;
            }}
            
            QScrollBar::handle:horizontal {{
                background: {COLORS["border"]};
                min-width: 20px;
                border-radius: 6px;
            }}
            
            QScrollBar::handle:horizontal:hover {{
                background: #AAAAAA;
            }}
            
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                border: none;
                background: none;
                width: 0px;
            }}
            
            QCheckBox {{
                color: {COLORS["text_primary"]};
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
            }}
            
            QFrame {{
                border-radius: 8px;
            }}
        """)
        
        # Create central widget and main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        
        # Create header - with reduced height and no shadow
        header_widget = QFrame()
        header_widget.setFixedHeight(70)  # Fixed height to prevent expansion
        header_widget.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS["background"]};
                border-radius: 0;
                border: none;
                border-bottom: 1px solid {COLORS["border"]};
            }}
        """)
        
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(20, 10, 20, 10)
        header_layout.setSpacing(15)
        
        # Modern branding section (left)
        branding_container = QWidget()
        branding_container.setStyleSheet("background: transparent; border: none;")
        branding_layout = QHBoxLayout(branding_container)
        branding_layout.setContentsMargins(0, 0, 0, 0)
        branding_layout.setSpacing(15)
        
        # Logo with modern design
        logo_label = QLabel()
        logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources", "images", "Pentora_logo.png")
        
        if os.path.exists(logo_path):
            logo_pixmap = QPixmap(logo_path)
            if not logo_pixmap.isNull():
                # Use higher quality scaling with better size to prevent pixelation
                scaled_size = QSize(40, 40)  # Slightly larger size for better quality
                logo_pixmap = logo_pixmap.scaled(scaled_size, 
                                               Qt.KeepAspectRatio, 
                                               Qt.SmoothTransformation)
                logo_label.setPixmap(logo_pixmap)
                logo_label.setFixedSize(scaled_size)
                logo_label.setScaledContents(False)  # Don't let the label auto-scale
                logo_label.setAlignment(Qt.AlignCenter)
            else:
                # Use Material Icon for shield
                logo_label = MaterialIcon.get_icon("security", size=32, color=COLORS['primary'])
        else:
            # Use Material Icon for shield
            logo_label = MaterialIcon.get_icon("security", size=32, color=COLORS['primary'])
            
        logo_label.setStyleSheet("background: transparent; border: none;")
        
        # Title with modern typography
        title_label = QLabel("Pentora")
        title_font = QFont("SF Pro Display", 16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet(f"color: {COLORS['primary']}; background: transparent; border: none;")
        
        branding_layout.addWidget(logo_label)
        branding_layout.addWidget(title_label)
        
        # Center section with app subtitle
        center_container = QWidget()
        center_container.setStyleSheet("background: transparent; border: none;")
        center_layout = QVBoxLayout(center_container)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(1)
        center_layout.setAlignment(Qt.AlignCenter)
        
        subtitle_label = QLabel("Advanced Vulnerability Scanner")
        subtitle_font = QFont("SF Pro Text", 11)
        subtitle_label.setFont(subtitle_font)
        subtitle_label.setStyleSheet(f"color: {COLORS['text_secondary']}; background: transparent; border: none;")
        subtitle_label.setAlignment(Qt.AlignCenter)
        
        center_layout.addWidget(subtitle_label)
        
        # User profile section (right) with reduced height and no shadow
        self.user_container = QFrame()
        self.user_container.setStyleSheet(f"""
            QFrame {{
                background-color: rgba(255, 255, 255, 0.05);
                border-radius: 20px;
                border: 1px solid {COLORS['border']};
            }}
            QFrame:hover {{
                background-color: rgba(255, 255, 255, 0.1);
            }}
        """)
        self.user_container.setCursor(QCursor(Qt.PointingHandCursor))
        self.user_container.mousePressEvent = self.show_user_menu
        
        user_layout = QHBoxLayout(self.user_container)
        user_layout.setContentsMargins(10, 5, 12, 5)
        user_layout.setSpacing(8)
        
        # User avatar with circular frame
        self.user_avatar = QLabel()
        self.user_avatar.setFixedSize(32, 32)
        self.user_avatar.setStyleSheet(f"""
            QLabel {{
                background-color: {COLORS['primary']}40;
                color: {COLORS['primary']};
                border-radius: 16px;
                font-size: 16px;
                font-weight: bold;
            }}
        """)
        self.user_avatar.setAlignment(Qt.AlignCenter)
        
        # Use Material Icon for avatar
        font = QFont(MaterialIcon.MATERIAL_ICONS_FONT_FAMILY)
        font.setPixelSize(24)
        self.user_avatar.setFont(font)
        self.user_avatar.setText("account_circle")  # Material icon ligature
        
        # User name with nice typography
        self.user_name = QLabel("Guest")
        user_name_font = QFont("SF Pro Text", 11)
        self.user_name.setFont(user_name_font)
        self.user_name.setStyleSheet(f"color: {COLORS['text_primary']}; background: transparent; border: none;")
        
        user_layout.addWidget(self.user_avatar)
        user_layout.addWidget(self.user_name)
        
        # Add all sections to header layout
        header_layout.addWidget(branding_container)
        header_layout.addWidget(center_container, 1)  # Center takes available space
        header_layout.addWidget(self.user_container, 0, Qt.AlignRight)
        
        # Add header to main layout
        self.main_layout.addWidget(header_widget)
        
        # Create stacked widget for auth and main content with extra spacing
        self.content_stack = QStackedWidget()
        self.main_layout.addSpacing(5)  # Add space between header and content
        self.main_layout.addWidget(self.content_stack)
    
    def create_main_content(self):
        """Create enhanced main application content with modern styling"""
        # Container for the main content
        container = QWidget()
        main_layout = QVBoxLayout(container)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        
        # Create normal Pentora main window
        self.pentora_window = PentoraMainWindow()
        
        # Extract the tab widget from the central widget
        central_widget = self.pentora_window.centralWidget()
        original_layout = central_widget.layout()
        
        # Find the tab widget
        tab_widget = None
        for i in range(original_layout.count()):
            item = original_layout.itemAt(i)
            if isinstance(item.widget(), QTabWidget):
                tab_widget = item.widget()
                break
        
        if not tab_widget:
            # Fallback if we can't find the tab widget
            return container
        
        # Create our modern version of the tab widget
        modern_tabs = ModernTabWidget()
        
        # Copy all tabs from the original tab widget
        tab_count = tab_widget.count()
        tabs_to_copy = []
        
        # First, gather info about all tabs without modifying original
        for i in range(tab_count):
            title = tab_widget.tabText(i)
            widget = tab_widget.widget(i)
            tabs_to_copy.append((title, widget))
        
        # Now add each tab to our modern tab widget
        for title, widget in tabs_to_copy:
            # Clone the widget for our modern tabs to avoid removing from original
            modern_tabs.addTab(widget, title)
            
            # Enhance the widget's appearance
            self._enhance_tab_content(widget)
        
        # Add to main layout
        main_layout.addWidget(modern_tabs)
        
        return container
    
    def show_auth_screen(self):
        """Show the authentication screen with transition"""
        # Prepare animation
        self.content_stack.setCurrentWidget(self.auth_manager)
        
        # Update user info in header
        self.user_avatar.setText("account_circle")  # Material icon ligature
        self.user_name.setText("Guest")
    
    def show_main_content(self):
        """Show the main application content with transition"""
        # Prepare animation
        self.content_stack.setCurrentWidget(self.main_content)
        
        # Update user info in header
        current_user = self.auth_manager.get_current_user()
        if current_user:
            # Use Material Icon for person
            self.user_avatar.setText("person")
            self.user_name.setText(current_user['username'])
    
    def on_auth_successful(self, user_id, username):
        """Handle successful authentication with enhanced feedback"""
        # Update user info in header
        # Use Material Icon for logged in user
        self.user_avatar.setText("person")
        self.user_avatar.setStyleSheet(f"""
            QLabel {{
                background-color: {COLORS['primary']}40;
                color: {COLORS['primary']};
                border-radius: 16px;
                font-size: 16px;
                font-weight: bold;
            }}
        """)
        self.user_name.setText(username)
        
        # Show main content with animation
        self.show_main_content()
    
    def on_auth_logout(self):
        """Handle logout with transition"""
        # Show auth screen with animation
        QTimer.singleShot(300, self.show_auth_screen)

    def _enhance_tab_content(self, widget):
        """Apply modern styling to tab content"""
        # Add padding around the tab content
        if hasattr(widget, 'layout') and widget.layout() is not None:
            widget.layout().setContentsMargins(20, 20, 20, 20)
            widget.layout().setSpacing(15)
            
            # Enhance all direct child widgets of the tab
            for i in range(widget.layout().count()):
                item = widget.layout().itemAt(i)
                if item.widget():
                    child = item.widget()
                    
                    # Special handling for frames in network scan tab
                    if isinstance(child, QFrame):
                        if "Network" in widget.objectName() or "network" in widget.objectName():
                            # Process frames in network tab
                            child.raise_()  # Raise frame to proper stacking order
                        
                        # Process child layouts recursively
                        if child.layout():
                            self._process_child_layout(child.layout())
                            
    def _process_child_layout(self, layout):
        """Process nested widgets in layouts recursively"""
        if not layout:
            return
            
        for i in range(layout.count()):
            item = layout.itemAt(i)
            
            # Process widget
            if item.widget():
                child_widget = item.widget()
                
                # Handle specific widget types
                if isinstance(child_widget, QLineEdit) or isinstance(child_widget, QComboBox) or isinstance(child_widget, QSpinBox):
                    # Ensure input fields are on top by raising them in the widget stack
                    child_widget.raise_()
                elif isinstance(child_widget, QFrame):
                    # Process nested frames if they have layouts
                    if child_widget.layout():
                        self._process_child_layout(child_widget.layout())
            
            # Process nested layouts
            elif item.layout():
                self._process_child_layout(item.layout())

    def show_user_menu(self, event):
        """Show user menu when clicked"""
        # Only show options if user is logged in
        if not self.auth_manager.is_authenticated():
            return
            
        # Create menu
        menu = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{
                background-color: {COLORS['background']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                padding: 5px;
            }}
            QMenu::item {{
                padding: 8px 20px;
                border-radius: 4px;
            }}
            QMenu::item:selected {{
                background-color: {COLORS['primary']}20;
            }}
        """)
        
        # Add actions with Material Icons
        change_password_action = menu.addAction(MaterialIcon.get_qicon("lock", size=18), "Change Password")
        change_password_action.triggered.connect(self.show_change_password_dialog)
        
        menu.addSeparator()
        
        logout_action = menu.addAction(MaterialIcon.get_qicon("logout", size=18, color=COLORS['danger']), "Logout")
        logout_action.triggered.connect(self.auth_manager.on_logout)
        
        # Show menu at current cursor position
        menu.exec_(QCursor.pos())
    
    def show_change_password_dialog(self):
        """Show dialog to change password"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Change Password")
        dialog.setMinimumWidth(350)
        dialog.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS['background']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border']};
            }}
        """)
        
        layout = QVBoxLayout(dialog)
        
        # Add title with Material Icon
        title_layout = QHBoxLayout()
        title_layout.setContentsMargins(0, 0, 0, 10)
        title_layout.setSpacing(10)
        
        lock_icon = MaterialIcon.get_icon("lock", size=24, color=COLORS['primary'])
        title_layout.addWidget(lock_icon)
        
        title_label = QLabel("Change Your Password")
        title_font = QFont("SF Pro Display", 14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet(f"color: {COLORS['primary']};")
        title_layout.addWidget(title_label)
        
        layout.addLayout(title_layout)
        
        # Form layout for inputs
        form_layout = QFormLayout()
        form_layout.setSpacing(10)
        
        # Password fields with Material Icons
        current_password_layout = QHBoxLayout()
        current_password_layout.setSpacing(10)
        current_password_layout.setContentsMargins(0, 0, 0, 0)
        
        current_password_icon = MaterialIcon.get_icon("key", size=18, color=COLORS['text_secondary'])
        current_password_layout.addWidget(current_password_icon)
        
        self.current_password = QLineEdit()
        self.current_password.setEchoMode(QLineEdit.Password)
        self.current_password.setStyleSheet(STYLE_SHEETS["line_edit"])
        self.current_password.setMinimumHeight(35)
        self.current_password.setPlaceholderText("Enter current password")
        current_password_layout.addWidget(self.current_password)
        
        # New password with Material Icon
        new_password_layout = QHBoxLayout()
        new_password_layout.setSpacing(10)
        new_password_layout.setContentsMargins(0, 0, 0, 0)
        
        new_password_icon = MaterialIcon.get_icon("vpn_key", size=18, color=COLORS['text_secondary'])
        new_password_layout.addWidget(new_password_icon)
        
        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.Password)
        self.new_password.setStyleSheet(STYLE_SHEETS["line_edit"])
        self.new_password.setMinimumHeight(35)
        self.new_password.setPlaceholderText("Enter new password")
        new_password_layout.addWidget(self.new_password)
        
        # Confirm password with Material Icon
        confirm_password_layout = QHBoxLayout()
        confirm_password_layout.setSpacing(10)
        confirm_password_layout.setContentsMargins(0, 0, 0, 0)
        
        confirm_password_icon = MaterialIcon.get_icon("done_all", size=18, color=COLORS['text_secondary'])
        confirm_password_layout.addWidget(confirm_password_icon)
        
        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.Password)
        self.confirm_password.setStyleSheet(STYLE_SHEETS["line_edit"])
        self.confirm_password.setMinimumHeight(35)
        self.confirm_password.setPlaceholderText("Confirm new password")
        confirm_password_layout.addWidget(self.confirm_password)
        
        # Add fields to form
        form_layout.addRow("Current Password:", current_password_layout)
        form_layout.addRow("New Password:", new_password_layout)
        form_layout.addRow("Confirm Password:", confirm_password_layout)
        
        layout.addLayout(form_layout)
        
        # Status label for messages
        self.change_password_status = QLabel("")
        self.change_password_status.setStyleSheet(f"color: {COLORS['danger']};")
        layout.addWidget(self.change_password_status)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        cancel_button = QPushButton("Cancel")
        cancel_button.setIcon(MaterialIcon.get_qicon("close", size=18))
        cancel_button.setStyleSheet(STYLE_SHEETS["secondary_button"])
        cancel_button.clicked.connect(dialog.reject)
        
        save_button = QPushButton("Save")
        save_button.setIcon(MaterialIcon.get_qicon("save", size=18))
        save_button.setStyleSheet(STYLE_SHEETS["primary_button"])
        save_button.clicked.connect(lambda: self.change_password(dialog))
        
        button_layout.addWidget(cancel_button)
        button_layout.addWidget(save_button)
        
        layout.addLayout(button_layout)
        
        # Show dialog
        dialog.exec_()
        
    def change_password(self, dialog):
        """Change user password"""
        current_password = self.current_password.text()
        new_password = self.new_password.text()
        confirm_password = self.confirm_password.text()
        
        # Validate inputs
        if not current_password or not new_password or not confirm_password:
            self.change_password_status.setText("All fields are required")
            return
            
        if new_password != confirm_password:
            self.change_password_status.setText("New passwords do not match")
            return
            
        # Validate password strength
        validation = self.auth_manager.user_manager.validate_password(new_password)
        if not validation["valid"]:
            self.change_password_status.setText("Password must be at least 8 characters with uppercase, lowercase, and numbers")
            return
            
        try:
            # Get current user
            user = self.auth_manager.get_current_user()
            user_id = user.get("user_id")
            
            # Verify current password
            user_data = self.auth_manager.user_manager.users["users"][user_id]
            if not self.auth_manager.user_manager.verify_password(current_password, user_data["salt"], user_data["hash"]):
                self.change_password_status.setText("Current password is incorrect")
                return
                
            # Update password
            salt, hash_value = self.auth_manager.user_manager.hash_password(new_password)
            user_data["salt"] = salt
            user_data["hash"] = hash_value
            
            # Save changes
            self.auth_manager.user_manager.save_users()
            
            # Show success message
            QMessageBox.information(self, "Success", "Password changed successfully")
            dialog.accept()
            
        except Exception as e:
            self.change_password_status.setText(f"Error: {str(e)}")

def main():
    """Main function to start the enhanced application with authentication"""
    app = QApplication(sys.argv)
    
    # Set application-wide properties
    app.setApplicationName("Pentora")
    app.setApplicationDisplayName("Pentora Vulnerability Scanner")
    
    # Set consistent font
    app.setFont(QFont("SF Pro Text", 10))
    
    # Initialize Material Icons
    MaterialIcon.initialize()
    
    # Set application icon
    icon_path = get_app_icon_path()
    if os.path.exists(icon_path):
        app_icon = QIcon(icon_path)
        app.setWindowIcon(app_icon)
    
    # Create and show main window with auth
    window = PentoraAuthApp()
    window.show()
    sys.exit(app.exec_()) 