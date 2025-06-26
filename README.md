# Secure Login System

A secure login and registration system built with **Flask**, featuring user roles, reCAPTCHA protection, session handling, and account lockout after multiple failed login attempts. Developed as part of my cybersecurity internship project.

## Features

- 🔐 Secure registration and login with hashed passwords (bcrypt)
- 👤 Role-based access: Admin & User dashboards
- 🔄 Session-based authentication
- ⚠️ Account lockout after 5 failed login attempts
- 🧠 Google reCAPTCHA v2 integration to prevent bot abuse
- 📋 Flash messages for user feedback
- 🛡️ Fully built with cybersecurity best practices in mind

## Tech Stack

- Python 3.x
- Flask
- Flask-WTF + WTForms
- SQLite
- Bcrypt
- Google reCAPTCHA v2

## How to Run the App Locally

1. **Clone the repository**:

   ```bash
   git clone https://github.com/Luc-eng001/secure-login-system.git
   cd secure-login-system

   ```

2. **Create virtual environment**:

   python -m venv venv
   source venv/bin/activate # On Windows use: venv\Scripts\activate

3. **Install Dependencies**:

   pip install -r requirements.txt

4. **Run the App**:

   python app.py

5. **Visit your browser**:

   http://127.0.0.1:5000

**Notes**
Ensure your reCAPTCHA keys are valid for localhost or your deployment domain.

Delete users.db if schema changes and re-run the app to recreate it.

reCAPTCHA can break form validation if incorrectly configured.

Connect with me: https://www.linkedin.com/in/luc-omar-24018b2a5/
