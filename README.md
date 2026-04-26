# LicenseHub

**Production-ready licensing, invoicing & monetization backend for developers.**

Built with FastAPI. Deploy in minutes. Start selling your software today.

---

![Dashboard Preview](https://via.placeholder.com/900x480/0f1117/3b82f6?text=LicenseHub+Dashboard+Preview)

---

## What is LicenseHub?

LicenseHub is a complete backend system for developers who want to sell and protect their software. Instead of spending weeks building auth, invoicing, and license management yourself — clone this, configure your `.env`, and you're ready to sell.

Works with any product: desktop apps, games, web tools, scripts, or SaaS.

---

## Features

### License management
- Generate unique license keys (16-character, collision-safe)
- Bind licenses to specific device IDs to prevent sharing
- Set expiry in days or make them permanent
- Revoke any license instantly via API
- Validate licenses from your app with a single HTTP call

### Invoice system
- Create invoices with customer name, email, amount, and currency
- Automatic email delivery on invoice creation
- Mark invoices as paid — triggers payment confirmation email and webhook
- Full invoice history per user

### Webhooks
- Fires a signed POST request to your URL when an invoice is paid
- HMAC-SHA256 signature for security — verify the request came from LicenseHub
- Works with Zapier, Make.com, Stripe webhooks, or your own backend
- Built-in test ping so you can verify your endpoint before going live

### Authentication
- User registration with email verification
- Secure login with JWT tokens (24-hour expiry)
- Forgot password / reset password via email
- Change password from the dashboard
- All passwords hashed with bcrypt

### Email automation
- Connect your own Gmail or SMTP account
- Credentials encrypted at rest with Fernet (AES-128)
- Custom email templates per user
- Sends: invoice creation, payment confirmation, account verification, password reset

### Admin API
- Generate license keys
- Revoke licenses
- View all users, invoices, and licenses
- All admin endpoints protected by secret key

---

## Tech stack

| Layer | Technology |
|---|---|
| Framework | FastAPI (Python 3.11) |
| Database | SQLite (dev) / PostgreSQL (production) |
| Auth | JWT via python-jose |
| Encryption | Fernet (cryptography) |
| Password hashing | bcrypt via passlib |
| Email | SMTP (Gmail-compatible) |
| Frontend | Pure HTML/CSS/JS — no build step |
| Deploy | Docker, Railway, any Linux VPS |

---

## Quick start

### 1. Clone the repository

```bash
git clone https://github.com/your-username/licensehub.git
cd licensehub
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment variables

Create a `.env` file in the project root:

```env
JWT_SECRET=your_long_random_secret_here
ADMIN_SECRET=your_admin_key_here
FERNET_KEY=your_fernet_key_here
ADMIN_EMAIL=your_gmail@gmail.com
EMAIL_PASSWORD=your_gmail_app_password
```

To generate a valid Fernet key:

```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```

### 4. Run the server

```bash
uvicorn main:app --reload
```

Visit `http://localhost:8000` — the landing page will load.
API docs are at `http://localhost:8000/api/docs`.

---

## Docker (recommended for production)

```bash
# Build and start
docker compose up -d

# Stop
docker compose down
```

The app runs on port `8000`. Put Nginx or Caddy in front of it for HTTPS.

---

## License validation — integrate into your app

One API call from your application checks whether a license is valid:

```python
import requests

response = requests.get("https://your-domain.com/api/check-license", params={
    "code":      "YOUR-LICENSE-KEY",
    "device_id": get_machine_id()  # any unique string for this machine
})

if response.json()["valid"]:
    launch_app()
else:
    show_purchase_screen()
```

Works in Python, JavaScript, Go, C#, Unity, or any HTTP client.

---

## Webhook integration

Configure a webhook URL in the dashboard. When any invoice is marked paid, LicenseHub sends:

```json
{
  "event": "invoice.paid",
  "timestamp": "2025-04-26T10:30:00Z",
  "data": {
    "invoice_id": 42,
    "customer_name": "Acme Corp",
    "customer_email": "billing@acme.com",
    "total": 299.0,
    "currency": "USD"
  }
}
```

Every request includes `X-LicenseHub-Signature: sha256=<hmac>` so you can verify it came from LicenseHub.

---

## API overview

### Public endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/register` | Register a new user |
| `POST` | `/api/login` | Login and get JWT token |
| `GET` | `/api/verify` | Verify email address |
| `POST` | `/api/forgot-password` | Request password reset |
| `POST` | `/api/reset-password` | Reset password with token |
| `GET` | `/api/check-license` | Validate a license key |

### Authenticated endpoints (require `Authorization: Bearer <token>`)

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/invoice` | Create a new invoice |
| `GET` | `/api/invoices` | List your invoices |
| `POST` | `/api/invoice/{id}/paid` | Mark invoice as paid |
| `POST` | `/api/activate` | Activate a license key |
| `GET` | `/api/my-license` | Get your license status |
| `POST` | `/api/smtp` | Save SMTP credentials |
| `POST` | `/api/webhook` | Save webhook URL |
| `GET` | `/api/webhook` | Get webhook config |
| `DELETE` | `/api/webhook` | Remove webhook |
| `POST` | `/api/webhook/test` | Send test webhook |
| `POST` | `/api/change-password` | Change your password |

### Admin endpoints (require `?admin_secret=YOUR_SECRET`)

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/admin/generate-license` | Generate a license key |
| `POST` | `/api/admin/revoke` | Revoke a license |
| `GET` | `/api/admin/licenses` | List all licenses |
| `GET` | `/api/admin/users` | List all users |
| `GET` | `/api/admin/invoices` | List all invoices |

---

## Production deployment checklist

- [ ] Set strong, random values for all `.env` secrets
- [ ] Switch to PostgreSQL (`DATABASE_URL` in `database.py`)
- [ ] Put the app behind Nginx/Caddy with HTTPS
- [ ] Set `uvicorn --workers 4` for concurrency
- [ ] Use Docker or systemd to keep it running
- [ ] Never commit `.env` to Git (it's in `.gitignore` already)

---

## Project structure

```
.
├── main.py            # All API routes
├── models.py          # SQLAlchemy database models
├── database.py        # DB engine and session
├── auth.py            # JWT token creation and verification
├── security.py        # Password hashing, Fernet encryption
├── email_utils.py     # SMTP email sending
├── license_utils.py   # License key generation
├── webhook_utils.py   # Webhook delivery (background thread, HMAC-signed)
├── requirements.txt   # Python dependencies (pinned versions)
├── Dockerfile         # Container build
├── docker-compose.yml # One-command local dev / production
├── templates/         # HTML pages (Jinja2)
│   ├── index.html     # Landing page
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html # Full user dashboard
│   └── forgot_password.html
└── static/
    └── css/
        └── auth.css   # Shared auth page styles
```

---

## Security notes

- JWT secrets must be long and random (32+ characters)
- SMTP passwords are encrypted with Fernet before storage — never stored in plain text
- Admin endpoints check the secret on every request
- Webhook payloads are signed with HMAC-SHA256
- Email verification prevents fake accounts
- IDOR protection: users can only access their own invoices

---

## Support

For questions, bug reports, or feature requests, open a GitHub issue or contact the developer.

---

## License

Commercial use license. You may deploy this for your own products. Redistribution or resale requires the White Label license.
