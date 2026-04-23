# Pentora Authentication System

## Overview

This authentication system is designed for the Pentora vulnerability scanner application. It provides a secure, user-friendly login/registration system integrated directly into the main application window.

## Features

- **User Authentication**: Sign in with username or email and password
- **User Registration**: Create new accounts with validation
- **Password Reset**: Forgot password flow with verification code
- **Security**: Secure password hashing with bcrypt
- **Validation**: Real-time input validation for all fields
- **Modern UI**: Clean, responsive interface that matches the main application theme

## Components

The authentication system is composed of several modular components:

1. **UserManager** (`auth.py`): Core class for user management, authentication, and security
2. **LoginWidget** (`auth_ui.py`): Sign-in form with validation
3. **RegisterWidget** (`auth_ui_register.py`): Account creation form with password strength check
4. **ForgotPasswordWidget** (`auth_ui_forgot.py`): Password reset flow
5. **AuthenticationManager** (`auth_manager.py`): Manages authentication flow and integrates all components
6. **PentoraAuthApp** (`pentora_gui_auth.py`): Modified main window that incorporates authentication

## Usage

To use the authentication system, run the modified entry point:

```bash
python pentora_auth.py
```

This will launch the application with the authentication system integrated into the main window.

## Authentication Flow

1. Users start at the login screen
2. From login, they can:
   - Sign in with existing credentials
   - Navigate to registration to create a new account
   - Navigate to password reset if they forgot their password
3. After successful authentication, the main application UI is shown
4. The user can sign out at any time using the sign-out button in the user profile section

## Data Storage

User data is stored securely in a JSON file in the user's home directory (`~/.pentora/users.json`). Passwords are hashed using bcrypt with individual salts.

## Security Considerations

- Passwords are never stored in plaintext
- All user inputs are properly validated and sanitized
- Password strength is enforced and shown to users during registration
- Password reset codes expire after 30 minutes
- Constant-time password comparison is used to prevent timing attacks

## Customization

The system is designed to be easily customizable:
- The styling can be adjusted to match different themes
- The user storage backend can be replaced with a database
- Additional fields/requirements can be added to the registration form
- Two-factor authentication could be integrated with minimal changes 