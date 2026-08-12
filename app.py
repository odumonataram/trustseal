"""
TrustSeal - QR Code-Based Product Anti-Counterfeit System
==========================================================

Main Flask application entry point.

Handles:
- Administrator authentication
- Product registration
- QR code generation
- Product verification
- Scan logging
- Counterfeit detection
- Product management
- Dashboard statistics
- SQLite for local development
- PostgreSQL for Render production deployment
"""

import os
import uuid
from datetime import datetime, date
from functools import wraps

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

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# ============================================================
# APP CONFIGURATION
# ============================================================

app = Flask(__name__)


# ------------------------------------------------------------
# Secret key
#
# Render will use the SECRET_KEY environment variable.
# When running locally, the fallback value is used.
# ------------------------------------------------------------

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "dev-secret-key"
)


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

# Render provides DATABASE_URL when PostgreSQL is connected.
#
# Local computer:
#     SQLite will be used automatically.
#
# Render:
#     PostgreSQL will be used automatically.

database_url = os.environ.get(
    "DATABASE_URL",
    "sqlite:///trustseal.db"
)

# Some hosting providers may provide postgres://.
# SQLAlchemy expects postgresql://.

if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://",
        "postgresql://",
        1
    )


app.config["SQLALCHEMY_DATABASE_URI"] = database_url

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# ============================================================
# QR CODE STORAGE
# ============================================================

QR_FOLDER = os.path.join(
    "static",
    "qrcodes"
)

os.makedirs(
    QR_FOLDER,
    exist_ok=True
)


# ============================================================
# DATABASE
# ============================================================

db = SQLAlchemy(app)


# ============================================================
# DATABASE MODELS
# ============================================================

class Admin(db.Model):
    """
    Stores administrator login credentials.
    """

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

    Each product receives a unique UUID which is embedded
    in its QR verification URL.
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

    # One product can have many scan records.
    scans = db.relationship(
        "ScanLog",
        backref="product",
        lazy=True
    )

    def __repr__(self):
        return (
            f"<Product "
            f"{self.product_name} "
            f"[{self.product_id}]>"
        )


class ScanLog(db.Model):
    """
    Records every product QR verification.

    The number of scans is used as an anti-counterfeit
    indicator.
    """

    __tablename__ = "scan_logs"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    product_id = db.Column(
        db.String(36),
        db.ForeignKey(
            "products.product_id"
        ),
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
            f"<ScanLog "
            f"product={self.product_id} "
            f"at={self.scanned_at}>"
        )


# ============================================================
# APPLICATION SETTINGS
# ============================================================

SCAN_THRESHOLD = 3


# ============================================================
# LOGIN REQUIRED DECORATOR
# ============================================================

def login_required(f):
    """
    Redirects unauthenticated users to the login page.
    """

    @wraps(f)
    def decorated(*args, **kwargs):

        if "admin_id" not in session:

            flash(
                "Please log in to access the admin area.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        return f(*args, **kwargs)

    return decorated


# ============================================================
# QR CODE GENERATION
# ============================================================

def generate_qr_code(
    product_id: str,
    verify_url: str
) -> str:
    """
    Generates a QR code containing the complete
    product verification URL.

    Returns the relative path of the saved QR image.
    """

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4
    )

    qr.add_data(verify_url)

    qr.make(
        fit=True
    )

    img = qr.make_image(
        fill_color="#0d2b45",
        back_color="white"
    )

    filename = (
        f"{product_id}.png"
    )

    file_path = os.path.join(
        QR_FOLDER,
        filename
    )

    img.save(file_path)

    return file_path


# ============================================================
# PUBLIC ROUTES
# ============================================================

@app.route("/")
def home():
    """
    Landing page.
    """

    return render_template(
        "home.html"
    )


@app.route(
    "/verify",
    methods=["GET", "POST"]
)
def verify():
    """
    Consumer verification page.

    Allows a user to enter a product ID manually
    or arrive through the verification interface.
    """

    if request.method == "POST":

        product_id = request.form.get(
            "product_id",
            ""
        ).strip()

        if not product_id:

            flash(
                "Please enter a product ID.",
                "warning"
            )

            return redirect(
                url_for("verify")
            )

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


# ============================================================
# PRODUCT VERIFICATION
# ============================================================

@app.route(
    "/result/<product_id>"
)
def result(product_id):
    """
    Verifies a product.

    Process:
    1. Search for the product.
    2. If it does not exist, report counterfeit/unregistered.
    3. Record the verification scan.
    4. Count total scans.
    5. Check expiry.
    6. Determine the final status.
    """

    product = Product.query.filter_by(
        product_id=product_id
    ).first()

    # --------------------------------------------------------
    # Product not found
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Record scan
    # --------------------------------------------------------

    scan = ScanLog(
        product_id=product_id,
        ip_address=request.remote_addr
    )

    db.session.add(scan)

    db.session.commit()

    # --------------------------------------------------------
    # Count scans
    # --------------------------------------------------------

    scan_count = ScanLog.query.filter_by(
        product_id=product_id
    ).count()

    # --------------------------------------------------------
    # Check expiry
    # --------------------------------------------------------

    today = date.today()

    expired = (
        product.expiry_date < today
    )

    # --------------------------------------------------------
    # Determine status
    # --------------------------------------------------------

    if scan_count > SCAN_THRESHOLD:

        status = "suspicious"

        message = (
            f"This QR code has been scanned "
            f"{scan_count} times. "
            "Unusually high scan activity may indicate "
            "that the QR code has been duplicated. "
            "Treat with caution."
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


# ============================================================
# ADMIN LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():
    """
    Administrator login page.
    """

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

        if (
            admin
            and check_password_hash(
                admin.password,
                password
            )
        ):

            session["admin_id"] = admin.id

            session["admin_name"] = (
                admin.username
            )

            flash(
                "Welcome back, "
                + admin.username
                + "!",
                "success"
            )

            return redirect(
                url_for("dashboard")
            )

        flash(
            "Invalid username or password.",
            "danger"
        )

    return render_template(
        "login.html"
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():
    """
    Logs the administrator out.
    """

    session.clear()

    flash(
        "You have been logged out.",
        "info"
    )

    return redirect(
        url_for("home")
    )


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():
    """
    Displays all registered products.

    The scan count is calculated for EVERY product
    before the template is rendered.
    """

    products = Product.query.order_by(
        Product.registered_at.desc()
    ).all()

    # --------------------------------------------------------
    # Calculate scan count for every product
    # --------------------------------------------------------

    for product in products:

        product.scan_count = (
            ScanLog.query
            .filter_by(
                product_id=product.product_id
            )
            .count()
        )

    # IMPORTANT:
    # render_template MUST be outside the loop.

    return render_template(
        "dashboard.html",
        products=products,
        today=date.today()
    )


# ============================================================
# PRODUCT REGISTRATION
# ============================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
@login_required
def register_product():
    """
    Registers a new product and generates its QR code.
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

        # ----------------------------------------------------
        # Required-field validation
        # ----------------------------------------------------

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
                url_for(
                    "register_product"
                )
            )

        # ----------------------------------------------------
        # Convert dates
        # ----------------------------------------------------

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
                url_for(
                    "register_product"
                )
            )

        # ----------------------------------------------------
        # Validate date order
        # ----------------------------------------------------

        if exp_date <= prod_date:

            flash(
                "Expiry date must be after production date.",
                "danger"
            )

            return redirect(
                url_for(
                    "register_product"
                )
            )

        # ----------------------------------------------------
        # Generate unique product UUID
        # ----------------------------------------------------

        product_id = str(
            uuid.uuid4()
        )

        # ----------------------------------------------------
        # Generate verification URL
        #
        # IMPORTANT:
        #
        # Instead of hard-coding:
        #
        # 192.168.1.34:5000
        #
        # Flask automatically uses the current host.
        #
        # Local:
        # http://192.168.1.34:5000/result/...
        #
        # Render:
        # https://your-app.onrender.com/result/...
        # ----------------------------------------------------

        verify_url = url_for(
            "result",
            product_id=product_id,
            _external=True
        )

        # ----------------------------------------------------
        # Generate QR code
        # ----------------------------------------------------

        qr_path = generate_qr_code(
            product_id,
            verify_url
        )

        # ----------------------------------------------------
        # Create product record
        # ----------------------------------------------------

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
            f'Product "{product_name}" '
            "registered successfully!",
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


# ============================================================
# VIEW QR CODE
# ============================================================

@app.route(
    "/qr/<product_id>"
)
@login_required
def view_qr(product_id):
    """
    Displays the generated QR code.
    """

    product = Product.query.filter_by(
        product_id=product_id
    ).first_or_404()

    return render_template(
        "qr_view.html",
        product=product
    )


# ============================================================
# DOWNLOAD QR CODE
# ============================================================

@app.route(
    "/qr/download/<product_id>"
)
@login_required
def download_qr(product_id):
    """
    Downloads the QR code PNG file.
    """

    product = Product.query.filter_by(
        product_id=product_id
    ).first_or_404()

    return send_file(
        product.qr_image_path,
        as_attachment=True,
        download_name=(
            f"QR_{product.product_name}.png"
        )
    )


# ============================================================
# DELETE PRODUCT
# ============================================================

@app.route(
    "/delete/<product_id>",
    methods=["POST"]
)
@login_required
def delete_product(product_id):
    """
    Deletes a product and its associated scan logs.
    """

    product = Product.query.filter_by(
        product_id=product_id
    ).first_or_404()

    # Delete scan records first.

    ScanLog.query.filter_by(
        product_id=product_id
    ).delete()

    # Delete product.

    db.session.delete(product)

    db.session.commit()

    flash(
        "Product deleted.",
        "info"
    )

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# DEFAULT ADMIN ACCOUNT
# ============================================================

def seed_admin():
    """
    Creates the default administrator account
    if one does not already exist.
    """

    existing_admin = Admin.query.filter_by(
        username="admin"
    ).first()

    if not existing_admin:

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
            "username: admin | "
            "password: admin123"
        )


# ============================================================
# DATABASE INITIALISATION
# ============================================================

with app.app_context():

    db.create_all()

    seed_admin()


# ============================================================
# APPLICATION ENTRY POINT
# ============================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        debug=True,
        host="0.0.0.0",
        port=port
    )