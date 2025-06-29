# Secure 2FA Streamlit App

A modern web app demo for Two-Factor Authentication (TOTP) built with Streamlit, SQLite, and Python.  
Features user registration, login with password and TOTP, account lockout, audit logs, and an admin panel.

## Features

- User registration with password hashing (bcrypt)
- TOTP-based 2FA (compatible with Google Authenticator, Authy, etc.)
- QR code provisioning for easy setup
- Account lockout after 3 failed attempts
- Audit logging of login and admin actions
- Admin panel for user management and log viewing

## Requirements

- Python 3.8+
- See [`requirements.txt`](requirements.txt) for dependencies

## Installation

1. Clone the repository:
    ```sh
    git clone <your-repo-url>
    cd 2fa-streamlit-app
    ```

2. Install dependencies:
    ```sh
    pip install -r requirements.txt
    ```

3. Run the app:
    ```sh
    streamlit run app.py
    ```

## Usage

- **Register:** Create a new user and scan the QR code with your authenticator app.
- **Login:** Enter your username and password, then provide the 2FA code from your app.
- **Admin Panel:** Enter the admin code (`admin123` by default) in the sidebar to manage users and view logs.

## File Structure

- [`app.py`](app.py): Main Streamlit application
- [`database.py`](database.py): SQLite database functions
- [`requirements.txt`](requirements.txt): Python dependencies
- `users.db`: SQLite database file (auto-created)

## Security Notes

- Change the admin code in [`app.py`](app.py) for production use.
- Passwords are hashed with bcrypt.
- TOTP secrets are generated per user.

## License

MIT License
