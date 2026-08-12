"""
TrustSeal - QR Code-Based Product Anti-Counterfeit System
==========================================================
Main Flask application entry point.
Handles routing, authentication, product registration,
QR code generation, and verification logic.

Author: Final Year Project
"""

import os
import uuid
from datetime import datetime, date

import qrcode
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


# ── App Setup ──────────────────────────────────────────────────────────────────

app = Flask(__name__)

app.secret_key = "trustseal-secret-key-change-in-production"

# SQLite database stored in the project root
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///trustseal.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Folder where generated QR code images will be saved
QR_FOLDER = os.path.join("static", "qrcodes")
os.makedirs(QR_FOLDER, exist_ok=True)

db = SQLAlchemy(app)


# ── Database Models ────────────────────────────────────────────────────────────

class Admin(db.Model):
    """Stores administrator login credentials."""

    __tablename__ = "admins"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(200),
        nullable=False
    )

    def __repr__(self):
        return f"<Admin {self.username}>"


class Product(db.Model):
    """
    Stores registered product information.

    Each product receives a globally unique UUID that is embedded
    inside its QR code.
    """

    __tablename__ = "products"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    product_id = db.Column(
        db.String(36),
        unique=True,
        nullable=False
    )

    product_name = db.Column(
        db.String(150),
        nullable=False
    )

    batch_number = db.Column(
        db.String(50),
        nullable=False
    )

    manufacturer_name = db.Column(
        db.String(150),
        nullable=False
    )

    production_date = db.Column(
        db.Date,
        nullable=False
    )

    expiry_date = db.Column(
        db.Date,
        nullable=False
    )

    registered_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    qr_image_path = db.Column(
        db.String(300)
    )

    # One product can have many scan events
    scans = db.relationship(
        "ScanLog",
        backref="product",
        lazy=True
    )

    def __repr__(self):
        return f"<Product {self.product_name} [{self.product_id}]>"


class ScanLog(db.Model):
    """
    Records every time a QR code is scanned.

    High scan counts trigger the suspicious-product warning.
    """

    __tablename__ = "scan_logs"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    product_id = db.Column(
        db.String(36),
        db.ForeignKey("products.product_id"),
        nullable=False
    )

    scanned_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    ip_address = db.Column(
        db.String(50)
    )

    def __repr__(self):
        return (
            f"<ScanLog product={self.product_id} "
            f"at={self.scanned_at}>"
        )


# ── Configuration ──────────────────────────────────────────────────────────────

# Maximum number of normal scans before a product becomes suspicious.
SCAN_THRESHOLD = 3


# ── Authentication Helper ──────────────────────────────────────────────────────

def login_required(f):
    """
    Redirects users to the login page if they are not authenticated.
    """

    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):

        if "admin_id" not in session:
            flash(
                "Please log in to access the admin area.",
                "warning"
            )

            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated


# ── QR Code Generator ──────────────────────────────────────────────────────────

def generate_qr_code(product_id: str, verify_url: str) -> str:
    """
    Generates a QR code containing the product verification URL.

    Returns the relative path of the generated QR image.
    """

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4
    )

    qr.add_data(verify_url)
    qr.make(fit=True)

    img = qr.make_image(
        fill_color="#0d2b45",
        back_color="white"
    )

    filename = f"{product_id}.png"

    file_path = os.path.join(
        QR_FOLDER,
        filename
    )

    img.save(file_path)

    return file_path


# ── Public Routes ──────────────────────────────────────────────────────────────

@app.route("/")
def home():
    """Landing page."""

    return render_template("home.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    """
    Consumer verification page.

    Accepts a product ID through GET or POST.
    """

    if request.method == "POST":

        product_id = request.form.get(
            "product_id",
            ""
        ).strip()

        return redirect(
            url_for(
                "result",
                product_id=product_id
            )
        )

    product_id = request.args.get(
        "product_id",
        ""
    )

    return render_template(
        "verify.html",
        product_id=product_id
    )


@app.route("/result/<product_id>")
def result(product_id):
    """
    Verification result page.

    1. Searches for the product.
    2. If not found, marks it as counterfeit.
    3. If found, records the scan.
    4. Counts the total number of scans.
    5. Checks the expiry date.
    6. Determines the verification status.
    """

    product = Product.query.filter_by(
        product_id=product_id
    ).first()

    # Product does not exist
    if not product:

        return render_template(
            "result.html",
            product=None,
            status="counterfeit",
            message=(
                "This product was not found in our database. "
                "It may be counterfeit or unregistered."
            )
        )

    # Record the scan
    scan = ScanLog(
        product_id=product_id,
        ip_address=request.remote_addr
    )

    db.session.add(scan)
    db.session.commit()

    # Count total scans
    scan_count = ScanLog.query.filter_by(
        product_id=product_id
    ).count()

    # Check expiry
    today = date.today()

    expired = product.expiry_date < today

    # Determine status
    if scan_count > SCAN_THRESHOLD:

        status = "suspicious"

        message = (
            f"This QR code has been scanned {scan_count} times. "
            "Unusually high scan activity may indicate that the "
            "QR code has been duplicated. Treat with caution."
        )

    elif expired:

        status = "expired"

        message = (
            "This product has passed its expiry date."
        )

    else:

        status = "genuine"

        message = (
            "This product is verified as genuine."
        )

    return render_template(
        "result.html",
        product=product,
        status=status,
        message=message,
        scan_count=scan_count
    )


# ── Admin Authentication ───────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    """Admin login page."""

    if "admin_id" in session:

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        admin = Admin.query.filter_by(
            username=username
        ).first()

        if admin and check_password_hash(
            admin.password,
            password
        ):

            session["admin_id"] = admin.id

            session["admin_name"] = admin.username

            flash(
                "Welcome back, " + admin.username + "!",
                "success"
            )

            return redirect(
                url_for("dashboard")
            )

        else:

            flash(
                "Invalid username or password.",
                "danger"
            )

    return render_template(
        "login.html"
    )


@app.route("/logout")
def logout():
    """Logs the administrator out."""

    session.clear()

    flash(
        "You have been logged out.",
        "info"
    )

    return redirect(
        url_for("home")
    )


# ── Admin Dashboard ────────────────────────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    """
    Admin overview showing all registered products.

    The scan count is calculated for every product
    before the dashboard template is rendered.
    """

    products = Product.query.order_by(
        Product.registered_at.desc()
    ).all()

    # Attach scan count to EVERY product
    for p in products:

        p.scan_count = ScanLog.query.filter_by(
            product_id=p.product_id
        ).count()

    # IMPORTANT:
    # This must be outside the for loop.
    return render_template(
        "dashboard.html",
        products=products,
        today=date.today()
    )


# ── Product Registration ───────────────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
@login_required
def register_product():
    """
    Product registration form.

    Creates a unique product ID and QR code.
    """

    if request.method == "POST":

        product_name = request.form.get(
            "product_name",
            ""
        ).strip()

        batch_number = request.form.get(
            "batch_number",
            ""
        ).strip()

        manufacturer_name = request.form.get(
            "manufacturer_name",
            ""
        ).strip()

        production_date = request.form.get(
            "production_date",
            ""
        )

        expiry_date = request.form.get(
            "expiry_date",
            ""
        )

        # Validate required fields
        if not all([
            product_name,
            batch_number,
            manufacturer_name,
            production_date,
            expiry_date
        ]):

            flash(
                "All fields are required.",
                "danger"
            )

            return redirect(
                url_for("register_product")
            )

        # Convert dates
        try:

            prod_date = datetime.strptime(
                production_date,
                "%Y-%m-%d"
            ).date()

            exp_date = datetime.strptime(
                expiry_date,
                "%Y-%m-%d"
            ).date()

        except ValueError:

            flash(
                "Invalid date format.",
                "danger"
            )

            return redirect(
                url_for("register_product")
            )

        # Validate date order
        if exp_date <= prod_date:

            flash(
                "Expiry date must be after production date.",
                "danger"
            )

            return redirect(
                url_for("register_product")
            )

        # Generate UUID
        product_id = str(
            uuid.uuid4()
        )

        # ─────────────────────────────────────────────────────────
        # IMPORTANT QR CODE CHANGE
        # The QR code now points to the computer's local network IP
        # instead of 127.0.0.1.
        # ─────────────────────────────────────────────────────────

        verify_url = (
            f"http://192.168.1.34:5000/result/{product_id}"
        )

        # Generate QR code
        qr_path = generate_qr_code(
            product_id,
            verify_url
        )

        # Create product
        product = Product(
            product_id=product_id,
            product_name=product_name,
            batch_number=batch_number,
            manufacturer_name=manufacturer_name,
            production_date=prod_date,
            expiry_date=exp_date,
            qr_image_path=qr_path
        )

        db.session.add(product)

        db.session.commit()

        flash(
            f'Product "{product_name}" registered successfully!',
            "success"
        )

        return redirect(
            url_for(
                "view_qr",
                product_id=product_id
            )
        )

    return render_template(
        "register.html"
    )


# ── QR Code Routes ─────────────────────────────────────────────────────────────

@app.route("/qr/<product_id>")
@login_required
def view_qr(product_id):
    """Displays the generated QR code."""

    product = Product.query.filter_by(
        product_id=product_id
    ).first_or_404()

    return render_template(
        "qr_view.html",
        product=product
    )


@app.route("/qr/download/<product_id>")
@login_required
def download_qr(product_id):
    """Downloads the QR code PNG file."""

    product = Product.query.filter_by(
        product_id=product_id
    ).first_or_404()

    return send_file(
        product.qr_image_path,
        as_attachment=True,
        download_name=f"QR_{product.product_name}.png"
    )


# ── Delete Product ─────────────────────────────────────────────────────────────

@app.route("/delete/<product_id>", methods=["POST"])
@login_required
def delete_product(product_id):
    """Deletes a product and its scan logs."""

    product = Product.query.filter_by(
        product_id=product_id
    ).first_or_404()

    # Delete associated scan logs
    ScanLog.query.filter_by(
        product_id=product_id
    ).delete()

    # Delete product
    db.session.delete(product)

    db.session.commit()

    flash(
        "Product deleted.",
        "info"
    )

    return redirect(
        url_for("dashboard")
    )


# ── Database Initialisation ────────────────────────────────────────────────────

def seed_admin():
    """
    Creates a default administrator account
    on the first application run.
    """

    if not Admin.query.filter_by(
        username="admin"
    ).first():

        default_admin = Admin(
            username="admin",
            password=generate_password_hash(
                "admin123"
            )
        )

        db.session.add(
            default_admin
        )

        db.session.commit()

        print(
            "Default admin created -> "
            "username: admin | password: admin123"
        )


# ── Create Database ────────────────────────────────────────────────────────────

with app.app_context():

    db.create_all()

    seed_admin()


# ── Application Entry Point ────────────────────────────────────────────────────

if __name__ == "__main__":

    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )