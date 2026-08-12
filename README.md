# TrustSeal — QR Code-Based Product Anti-Counterfeit System

> Final Year Project | Computer Science
> Technology: Python · Flask · SQLite · qrcode · HTML/CSS/JavaScript

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Folder Structure](#3-folder-structure)
4. [Database Schema](#4-database-schema)
5. [How QR Codes Are Generated](#5-how-qr-codes-are-generated)
6. [How Verification Works](#6-how-verification-works)
7. [How the System Prevents Counterfeits](#7-how-the-system-prevents-counterfeits)
8. [Installation & Running](#8-installation--running)
9. [Default Credentials](#9-default-credentials)
10. [Expected System Pages](#10-expected-system-pages)

---

## 1. Project Overview

TrustSeal is a web-based product authentication system. Manufacturers register
products and receive unique QR codes to print on packaging. Consumers scan the
QR code with any smartphone camera; the system checks the database in real time
and returns an authenticity verdict.

**Key features**
- UUID-based product identification (no two products share an ID)
- Automatic QR code image generation (downloadable PNG)
- Real-time database lookup and scan-count heuristic
- Session-authenticated admin portal
- Clean, mobile-friendly UI (no frameworks required)

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────┐
│                     CLIENT SIDE                      │
│   Consumer Browser          Admin Browser            │
│   (verify / result)         (login / dashboard /     │
│                              register / qr_view)     │
└────────────────┬────────────────────┬───────────────┘
                 │  HTTP requests      │
                 ▼                    ▼
┌─────────────────────────────────────────────────────┐
│               FLASK APPLICATION  (app.py)            │
│                                                      │
│  Routes                                              │
│  ├── /                  → home()                     │
│  ├── /login             → login()                    │
│  ├── /logout            → logout()                   │
│  ├── /dashboard         → dashboard()                │
│  ├── /register          → register_product()         │
│  ├── /qr/<id>           → view_qr()                  │
│  ├── /qr/download/<id>  → download_qr()              │
│  ├── /verify            → verify()                   │
│  ├── /result/<id>       → result()      ← core logic │
│  └── /delete/<id>       → delete_product()           │
│                                                      │
│  Helpers                                             │
│  ├── generate_qr_code() — creates PNG via qrcode lib │
│  ├── login_required()   — session guard decorator    │
│  └── seed_admin()       — creates default admin      │
└─────────────────────────────────────────────────────┘
                 │  SQLAlchemy ORM
                 ▼
┌─────────────────────────────────────────────────────┐
│              SQLite DATABASE  (trustseal.db)          │
│                                                      │
│   admins      products      scan_logs                │
│   ─────────   ──────────    ──────────               │
│   id          id            id                       │
│   username    product_id    product_id (FK)          │
│   password    product_name  scanned_at               │
│               batch_number  ip_address               │
│               manufacturer                           │
│               production_date                        │
│               expiry_date                            │
│               registered_at                          │
│               qr_image_path                          │
└─────────────────────────────────────────────────────┘
                 │  file I/O
                 ▼
┌─────────────────────────────────────────────────────┐
│        static/qrcodes/   (QR code PNG images)        │
│        <product_uuid>.png                            │
└─────────────────────────────────────────────────────┘
```

---

## 3. Folder Structure

```
trustseal/
│
├── app.py                    # Main Flask application (all routes + logic)
├── requirements.txt          # Python dependencies
├── README.md                 # This file
│
├── trustseal.db              # SQLite database (auto-created on first run)
│
├── static/
│   ├── css/
│   │   └── style.css         # Main stylesheet (teal/ink palette)
│   ├── js/                   # (reserved for future JS modules)
│   └── qrcodes/              # Generated QR code PNG images
│       └── <uuid>.png
│
└── templates/                # Jinja2 HTML templates
    ├── base.html             # Shared layout (navbar, footer, flash messages)
    ├── home.html             # Landing / features page
    ├── login.html            # Admin login form
    ├── dashboard.html        # Admin product list + stats
    ├── register.html         # Product registration form
    ├── qr_view.html          # QR code display + download
    ├── verify.html           # Consumer verification entry page
    └── result.html           # Authenticity result display
```

---

## 4. Database Schema

### Table: `admins`

| Column   | Type         | Constraints          | Description                       |
|----------|--------------|----------------------|-----------------------------------|
| id       | INTEGER      | PRIMARY KEY          | Auto-increment row ID             |
| username | VARCHAR(80)  | UNIQUE, NOT NULL     | Admin login username              |
| password | VARCHAR(200) | NOT NULL             | Werkzeug bcrypt-hashed password   |

---

### Table: `products`

| Column            | Type         | Constraints      | Description                             |
|-------------------|--------------|------------------|-----------------------------------------|
| id                | INTEGER      | PRIMARY KEY      | Auto-increment row ID                   |
| product_id        | VARCHAR(36)  | UNIQUE, NOT NULL | UUID4 — core identifier, embedded in QR |
| product_name      | VARCHAR(150) | NOT NULL         | Product display name                    |
| batch_number      | VARCHAR(50)  | NOT NULL         | Manufacturer batch reference            |
| manufacturer_name | VARCHAR(150) | NOT NULL         | Name of the manufacturing company       |
| production_date   | DATE         | NOT NULL         | When the product was manufactured       |
| expiry_date       | DATE         | NOT NULL         | When the product expires                |
| registered_at     | DATETIME     | DEFAULT now()    | Timestamp of registration               |
| qr_image_path     | VARCHAR(300) |                  | Relative path to the QR PNG file        |

---

### Table: `scan_logs`

| Column     | Type        | Constraints                       | Description                  |
|------------|-------------|-----------------------------------|------------------------------|
| id         | INTEGER     | PRIMARY KEY                       | Auto-increment row ID        |
| product_id | VARCHAR(36) | FOREIGN KEY → products.product_id | Which product was scanned    |
| scanned_at | DATETIME    | DEFAULT now()                     | Timestamp of the scan event  |
| ip_address | VARCHAR(50) |                                   | IP address of the scanner    |

---

## 5. How QR Codes Are Generated

**Library used:** `qrcode` (Python, backed by Pillow for image output)

**Process (inside `generate_qr_code()` in app.py):**

1. A `QRCode` object is configured with:
   - `version=1` — minimum size; auto-grows via `fit=True`
   - `error_correction=ERROR_CORRECT_H` — 30 % of the code can be damaged and still scan correctly, making it suitable for physical labels
   - `box_size=10`, `border=4` — comfortable sizing for printing

2. The data embedded in the QR is the **full verification URL**, e.g.:
   ```
   http://127.0.0.1:5000/result/3f4a7c2e-1b8d-4e9a-b2c0-7d8e9f0a1b2c
   ```
   Scanning this URL with any smartphone camera opens the verification page directly — **no app required**.

3. The image is saved as a PNG in `static/qrcodes/<uuid>.png` and the path stored in the database.

---

## 6. How Verification Works

When a consumer scans a QR code or enters a product ID:

```
Consumer scans QR
      │
      ▼
Flask route: /result/<product_id>
      │
      ├─► Query database: SELECT * FROM products WHERE product_id = ?
      │
      ├─► NOT FOUND?
      │       └─► Return status = "counterfeit"  ✗
      │
      └─► FOUND?
              │
              ├─► INSERT scan record into scan_logs
              │
              ├─► COUNT scans for this product_id
              │
              ├─► count > SCAN_THRESHOLD (3)?
              │       └─► Return status = "suspicious"  ⚠️
              │
              ├─► product.expiry_date < today?
              │       └─► Return status = "expired"  ⏰
              │
              └─► Otherwise → Return status = "genuine"  ✅
```

The result page displays full product details alongside the status banner.

---

## 7. How the System Prevents Counterfeits

TrustSeal uses a **three-layer protection model**:

### Layer 1 — UUID Uniqueness
Each product is assigned a UUID4 (Universally Unique Identifier, version 4).
A UUID4 is a 128-bit random number; there are 2¹²² ≈ 5.3 × 10³⁶ possible values.
The probability of two products accidentally sharing an ID is negligibly small.
A counterfeiter cannot guess a valid product ID by trial and error.

### Layer 2 — Database Lookup
The UUID is meaningless without a matching database record. Even if a
counterfeiter copies the physical QR code from a genuine product, the copied
code is identical to the original, which leads to…

### Layer 3 — Scan-Count Heuristic
Every scan is recorded in `scan_logs`. A genuine product is typically
scanned once by the end consumer at the point of purchase. If the same QR code
is scanned more than `SCAN_THRESHOLD` (default: 3) times, the system raises
a warning. This catches:
- Counterfeits that copy the same QR code from a genuine product and distribute many copies
- QR codes printed in bulk from a single registration

**Note:** The threshold is configurable in `app.py` (`SCAN_THRESHOLD = 3`).
In a production system this could be set to 1 for single-use products.

---

## 8. Installation & Running

### Prerequisites
- Python 3.9 or higher
- pip (Python package manager)

### Step-by-step

```bash
# 1. Clone or download the project folder
cd trustseal

# 2. (Recommended) Create a virtual environment
python -m venv venv

# Activate on Windows:
venv\Scripts\activate

# Activate on macOS / Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py
```

The server starts at **http://127.0.0.1:5000**

On first run, `trustseal.db` is created automatically and the default admin
account is seeded.

---

## 9. Default Credentials

| Field    | Value    |
|----------|----------|
| Username | admin    |
| Password | admin123 |

⚠️ Change these before any public deployment by updating `seed_admin()` in `app.py`.

---

## 10. Expected System Pages

| URL                       | Page                        | Access  |
|---------------------------|-----------------------------|---------|
| `/`                       | Home / Landing Page         | Public  |
| `/login`                  | Admin Login                 | Public  |
| `/dashboard`              | Admin Product Dashboard     | Admin   |
| `/register`               | Product Registration Form   | Admin   |
| `/qr/<product_id>`        | QR Code View & Download     | Admin   |
| `/verify`                 | Consumer Verification Entry | Public  |
| `/result/<product_id>`    | Authenticity Result Display | Public  |

---

*TrustSeal — Designed and Implemented as a Final Year Computer Science Project*
