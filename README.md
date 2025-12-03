# AuthX – Advanced Authentication & Authorization System (Django + DRF)

AuthX is a production-grade authentication and authorization system built using **Django**, **Django REST Framework**, and **JWT (access + refresh tokens)** with advanced security features such as email verification, password reset, refresh token rotation, device tracking, and brute-force protection.

This project is designed as a complete reference for modern authentication flows used in real-world applications.

---

## 🚀 Features

### 🔐 **Authentication System**

* Custom User Model (extends `AbstractUser`)
* Registration with email verification
* Login with **email OR username**
* JWT Authentication (Access + Refresh Tokens)
* Refresh Token Rotation (secure)
* Refresh Token stored **hashed** in DB
* HttpOnly Cookie for refresh token
* Access token via Authorization header

### 📧 **Email System**

* Email verification using secure verification tokens
* Gmail SMTP integration
* Secure verification flow with token expiry

### 🔁 **Password Reset Module**

* Request password reset
* Custom reset token model
* Token validation endpoint
* Secure password reset with `set_password()`
* Reset token expiry + single use

### 💻 **Security Features**

* Password hashing
* Refresh token reuse detection
* Token rotation with hash comparison
* Token blacklist/revocation
* CSRF protection for refresh endpoint
* Device info tracking for refresh tokens
* Login history support (extendable)

---

## 🏗️ Tech Stack

* **Python 3.10+**
* **Django 5+**
* **Django REST Framework**
* **djangorestframework-simplejwt**
* **Gmail SMTP** (email service)
* **SQLite / PostgreSQL** (supported)

---

## 📂 Project Structure

```
authx/
 ├── authx/                # Django project settings
 ├── users/                # All authentication logic
 │     ├── models.py       # User, ResetToken, VerificationToken, RefreshToken
 │     ├── views.py        # Register, Login, JWT operations
 │     ├── serializers.py  # Register, Login, Token validators
 │     ├── utils.py        # Hashing, token helpers
 │     ├── email_service.py# Gmail SMTP email sender
 │     └── auth_helpers.py # JWT creation, rotation, validation helpers
 ├── manage.py
 └── requirements.txt
```

---

## ⚙️ Installation

### 1️⃣ Clone the project

```
git clone https://github.com/Jeevan1975/AuthX.git
cd AuthX
```

### 2️⃣ Create a virtual environment

```
python -m venv venv
source venv/bin/activate  # macOS / Linux
venv\Scripts\activate     # Windows
```

### 3️⃣ Install dependencies

```
pip install -r requirements.txt
```

### 4️⃣ Apply migrations

```
python manage.py makemigrations
python manage.py migrate
```

### 5️⃣ Configure Gmail SMTP

Edit `settings.py`:

```
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = "yourgmail@gmail.com"
EMAIL_HOST_PASSWORD = "your-app-password"
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER
```

### 6️⃣ Run the server

```
python manage.py runserver
```

---

## 📬 API Endpoints

### 🔹 **Registration**

```
POST /api/register/
```

Creates user as inactive and sends verification email.

### 🔹 **Email Verification**

```
GET /api/verify-email/?token=...
```

Activates account.

### 🔹 **Login**

```
POST /api/auth/token/
```

Returns access token + sets refresh token cookie.

### 🔹 **Refresh Token**

```
POST /api/auth/token/refresh/
```

Rotates refresh token and issues new access token.

### 🔹 **Logout**

```
POST /api/auth/logout/
```

Revokes current refresh token.

### 🔹 **Logout All Devices**

```
POST /api/auth/logout-all/
```

Revokes all active refresh tokens.

### 🔹 **Password Reset Request**

```
POST /api/password-reset/request/
```

Sends password reset email.

### 🔹 **Password Reset Validate**

```
POST /api/password-reset/validate/
```

Validates reset token.

### 🔹 **Password Reset Complete**

```
POST /api/password-reset/complete/
```

Resets password.

---

## 🔐 JWT Architecture (Summary)

### Access Token

* Lifetime: **10 minutes**
* Sent via: **Authorization header**
* Short-lived for security

### Refresh Token

* Lifetime: **14 days**
* Stored in DB hashed (`HMAC-SHA256`)
* Sent to client via **HttpOnly cookie**
* Rotated on each refresh
* Reuse detection included

### Refresh Reuse Detection

If an old refresh token is used:

* All user sessions are revoked
* User must login again

---
