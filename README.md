# Secure Password-less Authentication System

A secure and user-friendly authentication system designed to replace traditional passwords with modern, safer alternatives. This system ensures confidentiality, usability, and protection against common threats like phishing, brute-force attacks, and password reuse.


## Project Overview

Traditional passwords are vulnerable and increasingly unsuitable for secure authentication. This project aims to implement a **password-less authentication system** that:
- Improves security by eliminating passwords.
- Supports multiple 2FA-based authentication methods.
- Ensures a smooth, inclusive user experience.


## Objectives

- Replace traditional password-based authentication.
- Implement multiple secure, user-friendly login methods.
- Ensure secure data handling, storage, and transmission.
- Prevent common attack vectors like brute-force, injection, and CSRF.


## Authentication Methods

All logins are based on **Two-Factor Authentication (2FA)** using the user's **CPR number** (9-digit ID) as the first factor, and one of the following password-less methods as the second factor:

### 1. OTP via SMS
- 6-digit code valid for **5 minutes**.
- Max **3 attempts**.
- Printed to console (SMS simulation).

### 2. Magic Link via Email
- Secure **JWT-based** link.
- **Expires in 5 minutes**.
- Printed to console (email simulation).

### 3. Security Questions (Fallback)
- Two predefined questions.
- Answers hashed with **bcrypt (14 rounds)**.


## Functional Flow

### Registration
- User submits CPR, email, phone, and answers to security questions.
- Data is encrypted with **AES-256** and sent to backend.
- Backend:
  - Decrypts data, hashes answers.
  - Encrypts personal info using **Fernet**.
  - Sends **JWT-based email verification link** (printed to console).

### Email Verification
- User clicks the verification link.
- Backend validates the JWT and verifies the user.

### Login
- User enters CPR and selects method (OTP, Magic Link, Security Questions).
- Backend validates method and issues response (OTP code, Magic Link, or security questions).
- Upon correct response:
  - Issues **JWT access token** (valid for 15 minutes).
  - Stores it in **HTTP-only, SameSite-lax** secure cookie.

### Logout
- Access token is added to a blacklist.
- Cookie is deleted to end session.


## 🛡️ Security Features

| Feature | Description |
|--------|-------------|
| **AES-256 + Fernet + bcrypt** | Encrypts and hashes sensitive user data during transmission and storage. |
| **Rate Limiting** | 5 requests/minute per IP and per CPR using `slowapi`. |
| **CORS Restrictions** | Only allows frontend-originated requests. |
| **JWT + Secure Cookies** | Short-lived tokens stored securely (not in localStorage). |
| **Security Headers** | Prevents XSS, clickjacking, and MIME sniffing. |
| **Input Validation** | Ensures valid CPR, emai
