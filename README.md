# Licensing & Monetization Backend for Developers

A production-ready backend system for managing licenses, users, invoices, and email automation. Built with FastAPI, this project is designed to help developers quickly add monetization and access control to their software without building everything from scratch.

---

## Overview

This backend provides a complete foundation for selling and managing digital products. It includes a licensing system to control access, an invoicing system to track payments, and email automation for communication with users.

It is suitable for developers who want to:

* Sell software, games, or digital tools
* Protect products using license keys
* Automate billing and communication
* Build SaaS products faster

---

## Core Features

### License Management

* Generate unique license keys
* Activate licenses with expiration dates
* Support permanent licenses
* Bind licenses to a specific device to prevent sharing
* Revoke licenses at any time
* Validate licenses via API for integration with applications

### Authentication

* Secure user registration and login
* JWT-based authentication
* Protected API endpoints with user context

### Invoice System

* Create invoices with customer information
* Track payment status
* Mark invoices as paid

### Email Automation

* Send invoices automatically via SMTP
* Send payment confirmations
* Customizable email templates
* Supports Gmail App Password and standard SMTP credentials

### Admin Control

* Generate licenses using admin credentials
* Revoke licenses
* View all licenses in the system

---

## Use Cases

### Software and Game Developers

Integrate the license validation API into your application to control access. Distribute license keys to users and prevent unauthorized sharing with device binding.

### SaaS Builders

Use this backend as a starting point for subscription or access-based services. Manage users, licenses, and payments in one place.

### Freelancers and Digital Sellers

Automatically generate invoices and send them to clients. Track payment status and maintain a simple billing workflow.

---

## Project Structure

```
.
|-- main.py            # API routes and application logic
|-- models.py          # Database models
|-- database.py        # Database configuration
|-- auth.py            # JWT authentication
|-- security.py        # Encryption utilities
|-- email_utils.py     # Email sending logic
|-- license_utils.py   # License generation
|-- requirements.txt   # Dependencies
|__ .env               # Environment variables
```

---

## Installation

### 1. Clone the repository

```
git clone <your-repo-url>
cd <your-project>
```

---

### 2. Install dependencies

```
pip install -r requirements.txt
```

---

### 3. Configure environment variables

Create a `.env` file in the root directory:

```
JWT_SECRET=your_jwt_secret
ADMIN_SECRET=your_admin_secret
FERNET_KEY=your_fernet_key
ADMIN_EMAIL=your_email@gmail.com
```

Make sure the `FERNET_KEY` is a valid key generated using the Fernet library.

---

### 4. Run the application

```
uvicorn main:app --reload
```

---

### 5. Access API documentation

Open your browser and go to:

```
http://localhost:8000/docs
```

---

## Authentication

After logging in via the `/login` endpoint, you will receive a JWT token. Use this token in the request header:

```
Authorization: Bearer <your_token>
```

All protected endpoints require this header.

---

## License Flow Example

1. Admin generates a license key
2. User registers an account
3. User activates the license using the key and device ID
4. Application verifies license validity via API
5. License can be revoked if needed

---

## Invoice Flow Example

1. User creates an invoice
2. System sends invoice email automatically
3. Admin marks invoice as paid
4. System sends payment confirmation

---

## Deployment

This project can be deployed on any server that supports Python.

For production use, it is recommended to:

* Use PostgreSQL instead of SQLite
* Configure environment variables securely
* Run the app behind a reverse proxy (e.g., Nginx)
* Use process managers such as systemd or Docker

---

## Security Notes

* JWT secrets must be kept private
* SMTP credentials are encrypted before storage
* Do not expose your `.env` file
* Use HTTPS in production environments

---

## License

This project is intended for commercial use. Redistribution without permission is not allowed.

---

## Support

For questions or issues, please contact the developer.

---

This backend is designed to save development time and provide a solid foundation for building and monetizing software products.
