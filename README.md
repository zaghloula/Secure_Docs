# SecureDocs – Secure Document Management Platform

**SecureDocs** is a secure document management web platform built using **Python**, **Flask**, **HTML**, **CSS**, and **JavaScript**.  
It runs locally on a **XAMPP** environment with a **MySQL** database named `securedocs`.

---

## 🛡️ Security Features

The platform includes multiple modern security mechanisms:

- 🔒 **CSRF Protection**
- ✅ **2-Factor Authentication (2FA)**
- 🔐 **Password Strength Validation**
- 🧼 **Sanitization and Validation of Inputs**
- 🔐 **Hashed Passwords**
- 💾 **Prepared Statements** (to prevent SQL Injection)

---

## 🔐 Authentication Methods

SecureDocs supports **three authentication providers**:

- **Okta**
- **GitHub**
- **Google**

To enable these providers, you must set the following environment variables in a `.env` file:

```env
SECRET_KEY=your_flask_secret_key
OKTA_CLIENT_ID=your_okta_client_id
OKTA_CLIENT_SECRET=your_okta_client_secret
OKTA_ISSUER=your_okta_issuer_url
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
