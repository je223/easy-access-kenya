from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)
import time
import smtplib
from email.message import EmailMessage
from flask_wtf.csrf import CSRFProtect

import sqlite3
from datetime import date
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_from_directory,
    abort
)
import os
import uuid
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.secret_key = os.environ.get(
    "EASY_ACCESS_SECRET_KEY",
    "dev-secret-key-change-this"
)

# CSRF configuration
app.config["WTF_CSRF_ENABLED"] = True
app.config["WTF_CSRF_SECRET_KEY"] = app.secret_key

csrf = CSRFProtect(app)

DATABASE = "easy_access.db"
UPLOAD_FOLDER = "uploads/application_documents"

ALLOWED_DOCUMENT_EXTENSIONS = {
    "pdf",
    "doc",
    "docx",
    "jpg",
    "jpeg",
    "png"
}

MAX_DOCUMENT_SIZE = 5 * 1024 * 1024

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_DOCUMENT_SIZE

# =========================================
# EMAIL CONFIGURATION
# =========================================

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587


# =========================================
# SEND COMPANY APPLICATION EMAIL
# =========================================

def send_company_application_email(
    company_email,
    applicant_name,
    opportunity_title,
    institution,
    course,
    county,
    applicant_email,
    application_url
):

    sender_email = os.environ.get(
        "EASY_ACCESS_EMAIL"
    )

    sender_password = os.environ.get(
        "EASY_ACCESS_EMAIL_PASSWORD"
    )

    if not sender_email or not sender_password:
        print(
            "EMAIL ERROR: Sender email credentials are not configured."
        )
        return False

    message = EmailMessage()

    message["Subject"] = (
        "New Application Received – Easy Access Kenya"
    )

    message["From"] = sender_email
    message["To"] = company_email

    message.set_content(
        f"""
Hello,

A new application has been submitted through Easy Access Kenya.

Applicant Details
-----------------
Applicant Name: {applicant_name}
Opportunity: {opportunity_title}
Institution: {institution}
Course: {course}
County: {county}
Applicant Email: {applicant_email}

The applicant has completed and submitted their application.

View Application:
{application_url}

Please log in to your Easy Access Kenya company account
to review the full application and uploaded documents.

Regards,

Easy Access Kenya
Connecting Kenyans to opportunities.
"""
    )

    try:

        with smtplib.SMTP(
            SMTP_SERVER,
            SMTP_PORT
        ) as server:

            server.starttls()

            server.login(
                sender_email,
                sender_password
            )

            server.send_message(message)

        print(
            f"APPLICATION EMAIL SENT TO: {company_email}"
        )

        return True

    except Exception as error:

        print(
            f"EMAIL ERROR: {error}"
        )

        return False

# =========================================
# LOGIN
# =========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please enter your email and password.")
            return redirect(url_for("login"))

        connection = get_db()

        user = connection.execute("""
            SELECT *
            FROM users
            WHERE email = ?
        """, (email,)).fetchone()

        if user is None:
            connection.close()
            flash("Invalid email or password.")
            return redirect(url_for("login"))

        if not check_password_hash(
            user["password_hash"],
            password
        ):
            connection.close()
            flash("Invalid email or password.")
            return redirect(url_for("login"))

        # =========================================
        # BLOCKED ACCOUNT CHECK
        # =========================================

        account_status = (
            user["account_status"] or "Active"
        ).strip().lower()

        if account_status == "blocked":

            connection.close()

            flash(
                "Your account has been blocked by an administrator. "
                "Please contact Easy Access Kenya support."
            )

            return redirect(url_for("login"))

        # =========================================
        # COMPANIES USE COMPANY LOGIN
        # =========================================

        if user["account_type"] == "company":

            connection.close()

            flash("Please use the Company Login page.")

            return redirect(url_for("company_login"))

                # =========================================
        # RECORD LAST ACTIVITY
        # =========================================

        connection.execute("""
            UPDATE users
            SET last_activity = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (user["id"],))

        connection.commit()

        print(
            "DEBUG LAST ACTIVITY UPDATED FOR USER:",
            user["id"]
        )

        connection.close()

        # =========================================
        # CREATE USER SESSION
        # =========================================

        session["user_id"] = user["id"]
        session["account_type"] = user["account_type"]
        session["name"] = user["name"]

        flash("Login successful!")

        return redirect(url_for("dashboard"))

    return render_template("login.html")

# =========================================
# COMPANY LOGIN
# =========================================

@app.route("/company-login", methods=["GET", "POST"])
def company_login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please enter your company email and password.")
            return redirect(url_for("company_login"))

        connection = get_db()

        user = connection.execute("""
            SELECT *
            FROM users
            WHERE email = ?
            AND account_type = 'company'
        """, (email,)).fetchone()

        if user is None:
            connection.close()
            flash("Invalid company email or password.")
            return redirect(url_for("company_login"))

        # =========================================
        # CHECK PASSWORD
        # =========================================

        if not check_password_hash(
            user["password_hash"],
            password
        ):
            connection.close()
            flash("Invalid company email or password.")
            return redirect(url_for("company_login"))

        # =========================================
        # CHECK BLOCKED ACCOUNT
        # =========================================

        account_status = (
            user["account_status"] or "Active"
        ).strip().lower()

        if account_status == "blocked":
            connection.close()
            flash(
                "Your company account has been blocked by an administrator. "
                "Please contact Easy Access Kenya support."
            )
            return redirect(url_for("company_login"))

        # =========================================
        # CHECK COMPANY VERIFICATION
        # =========================================

        company_profile = connection.execute("""
            SELECT *
            FROM company_profiles
            WHERE user_id = ?
        """, (user["id"],)).fetchone()

        connection.close()

        if company_profile is None:
            flash("Company profile not found.")
            return redirect(url_for("company_login"))

        verification_status = (
            company_profile["verification_status"] or ""
        ).strip().lower()

        if verification_status == "blocked":
            flash(
                "Your company registration has been blocked by an administrator."
            )
            return redirect(url_for("company_login"))

        if verification_status == "rejected":
            flash(
                "Your company registration was rejected by an administrator."
            )
            return redirect(url_for("company_login"))

        if verification_status != "verified":
            flash(
                "Your company account is still awaiting verification."
            )
            return redirect(url_for("company_login"))

        # =========================================
        # COMPANY LOGIN SUCCESS
        # =========================================

        session["user_id"] = user["id"]
        session["account_type"] = user["account_type"]
        session["name"] = user["name"]

        flash("Verified Login — Welcome!")

        return redirect(url_for("company_dashboard"))

    return render_template("company_login.html")

      
# =========================================
# DATABASE
# =========================================

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def create_database():

    os.makedirs(
        app.config["UPLOAD_FOLDER"],
        exist_ok=True
    )

    connection = get_db()

    # =========================================
    # USERS TABLE
    # =========================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            account_type TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # =========================================
    # USERS TABLE UPGRADES
    # =========================================

    user_columns = [
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]

    if "account_status" not in user_columns:
        connection.execute("""
            ALTER TABLE users
            ADD COLUMN account_status TEXT DEFAULT 'Active'
        """)

    if "last_activity" not in user_columns:
        connection.execute("""
            ALTER TABLE users
            ADD COLUMN last_activity TIMESTAMP
        """)

    # =========================================
    # ADMINS TABLE
    # =========================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # =========================================
    # ADMIN SYSTEM UPGRADES
    # =========================================

    admin_columns = [
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(admins)"
        ).fetchall()
    ]

    if "role" not in admin_columns:
        connection.execute("""
            ALTER TABLE admins
            ADD COLUMN role TEXT DEFAULT 'main_admin'
        """)

    if "security_code_hash" not in admin_columns:
        connection.execute("""
            ALTER TABLE admins
            ADD COLUMN security_code_hash TEXT
        """)

    # Make the existing administrator the main administrator.
    connection.execute("""
        UPDATE admins
        SET role = 'main_admin'
        WHERE id = (
            SELECT MIN(id)
            FROM admins
        )
        AND (role IS NULL OR role = '')
    """)

    # Add admin profile photo column if it does not already exist
    admin_columns = [
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(admins)"
        ).fetchall()
    ]

    if "profile_photo" not in admin_columns:
        connection.execute(
            "ALTER TABLE admins ADD COLUMN profile_photo TEXT"
        )

    # =========================================
    # ADMIN PERMISSIONS
    # =========================================

    admin_columns = [
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(admins)"
        ).fetchall()
    ]

    permission_columns = {
        "can_manage_companies": 1,
        "can_manage_opportunities": 1,
        "can_manage_applications": 1,
        "can_view_users": 1,
        "can_manage_business_ideas": 1,
        "can_view_reports": 1
    }

    for column_name in permission_columns:

        if column_name not in admin_columns:

            connection.execute(f"""
                ALTER TABLE admins
                ADD COLUMN {column_name} INTEGER DEFAULT 0
            """)

    # Main administrator always has full permissions
    connection.execute("""
        UPDATE admins
        SET
            can_manage_companies = 1,
            can_manage_opportunities = 1,
            can_manage_applications = 1,
            can_view_users = 1,
            can_manage_business_ideas = 1,
            can_view_reports = 1
        WHERE role = 'main_admin'
    """)   


    # =========================================
    # COMPANY PROFILES TABLE
    # =========================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS company_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            company_name TEXT NOT NULL,
            contact_person TEXT,
            phone TEXT,
            location TEXT,
            verification_status TEXT DEFAULT 'Pending',
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            verified_at TIMESTAMP,

            FOREIGN KEY (user_id)
            REFERENCES users(id)
        )
    """)

    # =========================================
    # OPPORTUNITIES TABLE
    # =========================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS opportunities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            opportunity_type TEXT NOT NULL,
            company TEXT NOT NULL,
            county TEXT NOT NULL,
            course TEXT,
            industry TEXT,
            description TEXT NOT NULL,
            requirements TEXT,
            deadline TEXT,
            contact_email TEXT,
            posted_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (posted_by)
            REFERENCES users(id)
        )
    """)

    # Add new columns to existing opportunities databases
    existing_columns = [
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(opportunities)"
        ).fetchall()
    ]

    if "course" not in existing_columns:
        connection.execute(
            "ALTER TABLE opportunities ADD COLUMN course TEXT"
        )

    if "industry" not in existing_columns:
        connection.execute(
            "ALTER TABLE opportunities ADD COLUMN industry TEXT"
        )

    # =========================================
    # APPLICATIONS TABLE
    # =========================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            opportunity_id INTEGER NOT NULL,
            applicant_id INTEGER NOT NULL,
            cover_letter TEXT,
            status TEXT DEFAULT 'Pending',
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (opportunity_id)
            REFERENCES opportunities(id),

            FOREIGN KEY (applicant_id)
            REFERENCES users(id),

            UNIQUE(opportunity_id, applicant_id)
        )
    """)

    # =========================================
    # APPLICATION DOCUMENTS TABLE
    # =========================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS application_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id INTEGER NOT NULL,
            document_type TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (application_id)
            REFERENCES applications(id)
        )
    """)

    # =========================================
    # APPLICATION SYSTEM V2
    # =========================================
    # Add new application information fields
    # without deleting existing data.

    application_columns = [
        ("full_name", "TEXT"),
        ("email", "TEXT"),
        ("phone", "TEXT"),
        ("county", "TEXT"),
        ("town", "TEXT"),
        ("date_of_birth", "TEXT"),
        ("institution", "TEXT"),
        ("course", "TEXT"),
        ("education_level", "TEXT"),
        ("year_of_study", "TEXT"),
        ("graduation_year", "TEXT"),
        ("skills", "TEXT")
    ]

    existing_columns = connection.execute("""
        PRAGMA table_info(applications)
    """).fetchall()

    existing_column_names = {
        column["name"] for column in existing_columns
    }

    for column_name, column_type in application_columns:
        if column_name not in existing_column_names:
            connection.execute(
                f"ALTER TABLE applications ADD COLUMN {column_name} {column_type}"
            )

        # =========================================
    # NOTIFICATIONS TABLE
    # =========================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            notification_type TEXT DEFAULT 'general',
            opportunity_id INTEGER,
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
            REFERENCES users(id),

            FOREIGN KEY (opportunity_id)
            REFERENCES opportunities(id)
        )
    """)

    # =========================================
    # SAVE DATABASE CHANGES
    # =========================================

    connection.commit()
    connection.close()

# =========================================
# NOTIFICATION STATUS
# =========================================

@app.route("/notification-status")
def notification_status():

    if "user_id" not in session:
        return {
            "count": 0,
            "latest_id": 0
        }

    connection = get_db()

    notification_data = connection.execute("""
        SELECT
            COUNT(*) AS unread_count,
            COALESCE(MAX(id), 0) AS latest_id
        FROM notifications
        WHERE user_id = ?
        AND is_read = 0
    """, (
        session["user_id"],
    )).fetchone()

    connection.close()

    return {
        "count": notification_data["unread_count"],
        "latest_id": notification_data["latest_id"]
    }    

# =========================================
# HOME
# =========================================

@app.route("/")
def home():
    return render_template("index.html")



# =========================================
# COMPANY REGISTER
# =========================================

@app.route("/company-register", methods=["GET", "POST"])
def company_register():

    if request.method == "POST":

        company_name = request.form.get("company_name", "").strip()
        contact_person = request.form.get("contact_person", "").strip()
        phone = request.form.get("phone", "").strip()
        location = request.form.get("location", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not company_name or not email or not password:
            flash("Please fill in all required fields.")
            return redirect(url_for("company_register"))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("company_register"))

        if len(password) < 6:
            flash("Password must be at least 6 characters.")
            return redirect(url_for("company_register"))

        connection = get_db()

        existing_user = connection.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if existing_user:
            connection.close()
            flash("An account with this email already exists.")
            return redirect(url_for("company_register"))

        password_hash = generate_password_hash(password)

        cursor = connection.execute("""
            INSERT INTO users (
                name,
                email,
                password_hash,
                account_type
            )
            VALUES (?, ?, ?, ?)
        """, (
            company_name,
            email,
            password_hash,
            "company"
        ))

        user_id = cursor.lastrowid

        connection.execute("""
            INSERT INTO company_profiles (
                user_id,
                company_name,
                contact_person,
                phone,
                location,
                verification_status
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            company_name,
            contact_person,
            phone,
            location,
            "Pending"
        ))

        connection.commit()
        connection.close()

        flash("Company registration submitted. Your account is pending verification.")
        return redirect(url_for("company_login"))

    return render_template("company_register.html")


# =========================================
# REGISTER
# =========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        account_type = request.form.get("account_type", "")

        if not name or not email or not password or not confirm_password or not account_type:
            flash("Please fill in all fields.")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Password must be at least 6 characters.")
            return redirect(url_for("register"))

        # Companies must use the separate company registration page
        allowed_types = [
            "student",
            "job_seeker"
        ]

        if account_type not in allowed_types:
            flash("Please select a valid account type.")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        connection = get_db()

        try:

            connection.execute("""
                INSERT INTO users
                (name, email, password_hash, account_type)
                VALUES (?, ?, ?, ?)
            """, (
                name,
                email,
                password_hash,
                account_type
            ))

            connection.commit()

        except sqlite3.IntegrityError:

            connection.close()

            flash("An account with that email already exists.")
            return redirect(url_for("register"))

        connection.close()

        flash("Account created successfully! You can now login.")
        return redirect(url_for("login"))

    return render_template("register.html")

# =========================================
# DASHBOARD
# =========================================

# =========================================
# ADMIN LOGIN
# =========================================

@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():

    connection = get_db()

    # If no administrator exists yet, send the user
    # to the first-time administrator setup page.
    existing_admin = connection.execute("""
        SELECT id
        FROM admins
        LIMIT 1
    """).fetchone()

    connection.close()

    if existing_admin is None:
        return redirect(url_for("admin_setup"))

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please enter your admin email and password.")
            return redirect(url_for("admin_login"))

        connection = get_db()

        admin = connection.execute("""
            SELECT *
            FROM admins
            WHERE email = ?
        """, (email,)).fetchone()

        connection.close()

        if admin is None:
            flash("Invalid administrator credentials.")
            return redirect(url_for("admin_login"))

        if not check_password_hash(
            admin["password_hash"],
            password
        ):
            flash("Invalid administrator credentials.")
            return redirect(url_for("admin_login"))

        session["admin_id"] = admin["id"]
        session["admin_name"] = admin["name"]
        session["is_admin"] = True

        flash("Administrator login successful.")

        return redirect(url_for("admin_dashboard"))

    return render_template("admin_login.html")


# =========================================
# ADMIN PROFILE PHOTO
# =========================================

@app.route("/admin-profile-photo", methods=["POST"])
def admin_profile_photo():

    if not session.get("admin_id"):
        flash("Please login as administrator.")
        return redirect(url_for("admin_login"))

    photo = request.files.get("profile_photo")

    if not photo or photo.filename == "":
        flash("Please select a profile photo.")
        return redirect(url_for("admin_dashboard"))

    allowed_extensions = {
        "jpg",
        "jpeg",
        "png",
        "webp"
    }

    filename = secure_filename(photo.filename)

    if "." not in filename:
        flash("Invalid profile photo.")
        return redirect(url_for("admin_dashboard"))

    extension = filename.rsplit(".", 1)[1].lower()

    if extension not in allowed_extensions:
        flash("Please upload JPG, JPEG, PNG or WEBP.")
        return redirect(url_for("admin_dashboard"))

    admin_upload_folder = os.path.join(
        app.static_folder,
        "uploads",
        "admin"
    )

    os.makedirs(admin_upload_folder, exist_ok=True)

    unique_filename = (
        str(uuid.uuid4())
        + "."
        + extension
    )

    photo_path = os.path.join(
        admin_upload_folder,
        unique_filename
    )

    photo.save(photo_path)

    connection = get_db()

    connection.execute("""
        UPDATE admins
        SET profile_photo = ?
        WHERE id = ?
    """, (
        unique_filename,
        session["admin_id"]
    ))

    connection.commit()
    connection.close()

    session["admin_profile_photo"] = unique_filename

    flash("Profile photo updated successfully.")

    return redirect(url_for("admin_dashboard"))


# =========================================
# ADMIN FIRST-TIME SETUP
# =========================================

@app.route("/admin-setup", methods=["GET", "POST"])
def admin_setup():

    connection = get_db()

    # Do not allow another first-time setup once
    # an administrator already exists.
    existing_admin = connection.execute("""
        SELECT id
        FROM admins
        LIMIT 1
    """).fetchone()

    if existing_admin:
        connection.close()
        flash("Administrator setup has already been completed.")
        return redirect(url_for("admin_login"))

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or not email or not password:
            connection.close()
            flash("Please fill in all required fields.")
            return redirect(url_for("admin_setup"))

        if password != confirm_password:
            connection.close()
            flash("Passwords do not match.")
            return redirect(url_for("admin_setup"))

        if len(password) < 8:
            connection.close()
            flash("Admin password must be at least 8 characters.")
            return redirect(url_for("admin_setup"))

        password_hash = generate_password_hash(password)

        connection.execute("""
            INSERT INTO admins (
                name,
                email,
                password_hash,
                role,
                security_code_hash,
                profile_photo,
                can_manage_companies,
                can_manage_opportunities,
                can_manage_applications,
                can_view_users,
                can_manage_business_ideas,
                can_view_reports
            )
            VALUES (
                ?,
                ?,
                ?,
                'main_admin',
                NULL,
                NULL,
                1,
                1,
                1,
                1,
                1,
                1
            )
        """, (
            name,
            email,
            password_hash
        ))

        connection.commit()
        connection.close()

        flash("Main Administrator account created successfully.")

        return redirect(url_for("admin_login"))

    connection.close()

    return render_template("admin_setup.html")


# =========================================
# ADMIN DASHBOARD
# =========================================

@app.route("/admin-dashboard")
def admin_dashboard():

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    total_companies = connection.execute("""
        SELECT COUNT(*)
        FROM company_profiles
    """).fetchone()[0]

    pending_companies = connection.execute("""
        SELECT COUNT(*)
        FROM company_profiles
        WHERE verification_status = 'Pending'
    """).fetchone()[0]

    verified_companies = connection.execute("""
        SELECT COUNT(*)
        FROM company_profiles
        WHERE verification_status = 'Verified'
    """).fetchone()[0]

    total_opportunities = connection.execute("""
        SELECT COUNT(*)
        FROM opportunities
    """).fetchone()[0]

    companies = connection.execute("""
        SELECT
            cp.id,
            cp.company_name,
            cp.contact_person,
            cp.phone,
            cp.location,
            cp.verification_status,
            cp.submitted_at,
            u.email
        FROM company_profiles cp
        JOIN users u
            ON cp.user_id = u.id
        ORDER BY cp.submitted_at DESC
    """).fetchall()

    connection.close()

    return render_template(
        "admin_dashboard.html",
        total_companies=total_companies,
        pending_companies=pending_companies,
        verified_companies=verified_companies,
        total_opportunities=total_opportunities,
        companies=companies
    )

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    if not user:
        conn.close()
        session.clear()
        return redirect(url_for("login"))

    # Companies use the Company Dashboard
    if user["account_type"] == "company":
        conn.close()
        return redirect(url_for("company_dashboard"))

    opportunities_count = conn.execute(
        "SELECT COUNT(*) FROM opportunities"
    ).fetchone()[0]

    application_count = conn.execute(
        "SELECT COUNT(*) FROM applications WHERE applicant_id = ?",
        (session["user_id"],)
    ).fetchone()[0]

    conn.close()

    return render_template(
        "dashboard.html",
        user=user,
        name=user["name"],
        account_type=user["account_type"],
        opportunity_count=opportunities_count,
        application_count=application_count
    )

# =========================================
# ADMIN OPPORTUNITIES
# =========================================

@app.route("/admin-opportunities")
def admin_opportunities():

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    opportunities = connection.execute("""
        SELECT
            id,
            title,
            opportunity_type,
            company,
            county,
            course,
            industry,
            deadline,
            contact_email,
            posted_by,
            created_at
        FROM opportunities
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return render_template(
        "admin_opportunities.html",
        opportunities=opportunities
    )

# ==============================
# ADMIN PENDING COMPANIES
# ==============================

@app.route("/admin-companies/pending")
def admin_pending_companies():

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    companies = connection.execute("""
        SELECT
            cp.id,
            cp.company_name,
            cp.contact_person,
            cp.phone,
            cp.location,
            cp.verification_status,
            cp.submitted_at,
            u.email
        FROM company_profiles cp
        JOIN users u
            ON cp.user_id = u.id
        WHERE cp.verification_status = 'Pending'
        ORDER BY cp.submitted_at DESC
    """).fetchall()

    connection.close()

    return render_template(
        "admin_pending_companies.html",
        companies=companies
    )

# ==============================
# ADMIN VERIFIED COMPANIES
# ==============================

@app.route("/admin-companies/verified")
def admin_verified_companies():

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    companies = connection.execute("""
        SELECT
            cp.id,
            cp.company_name,
            cp.contact_person,
            cp.phone,
            cp.location,
            cp.verification_status,
            cp.submitted_at,
            cp.verified_at,
            u.email
        FROM company_profiles cp
        JOIN users u
            ON cp.user_id = u.id
        WHERE cp.verification_status = 'Verified'
        ORDER BY cp.verified_at DESC, cp.submitted_at DESC
    """).fetchall()

    connection.close()

    return render_template(
        "admin_verified_companies.html",
        companies=companies
    )

# ==============================
# ADMIN USER MANAGEMENT
# ==============================

@app.route("/admin-users")
def admin_users():

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    # Add account status to users if it does not exist
    user_columns = [
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]

    if "account_status" not in user_columns:
        connection.execute("""
            ALTER TABLE users
            ADD COLUMN account_status TEXT DEFAULT 'Active'
        """)

    if "last_activity" not in user_columns:
        connection.execute("""
            ALTER TABLE users
            ADD COLUMN last_activity TIMESTAMP
        """)

    # Add account status to admins if it does not exist
    admin_columns = [
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(admins)"
        ).fetchall()
    ]

    if "account_status" not in admin_columns:
        connection.execute("""
            ALTER TABLE admins
            ADD COLUMN account_status TEXT DEFAULT 'Active'
        """)

    connection.commit()

    # Companies
    companies = connection.execute("""
        SELECT
            id,
            name,
            email,
            account_type,
            account_status,
            created_at
        FROM users
        WHERE account_type = 'company'
        ORDER BY id DESC
    """).fetchall()

    # Students
    students = connection.execute("""
    SELECT
        id,
        name,
        email,
        account_type,
        account_status,
        last_activity,
        created_at
    FROM users
    WHERE account_type = 'student'
    ORDER BY id DESC
""").fetchall()

    # Job seekers
    job_seekers = connection.execute("""
        SELECT
            id,
            name,
            email,
            account_type,
            account_status,
            created_at
        FROM users
        WHERE account_type = 'job_seeker'
        ORDER BY id DESC
    """).fetchall()

    # Only added/sub-admins.
    # Main Admin is deliberately excluded.
    added_admins = connection.execute("""
        SELECT
            id,
            name,
            email,
            role,
            account_status,
            created_at
        FROM admins
        WHERE role != 'main_admin'
           OR role IS NULL
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return render_template(
        "admin_users.html",
        companies=companies,
        students=students,
        job_seekers=job_seekers,
        added_admins=added_admins
    )

# ==============================
# BLOCK / UNBLOCK USER
# ==============================

@app.route("/admin-user-toggle-block/<int:user_id>", methods=["POST"])
def admin_user_toggle_block(user_id):

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    user = connection.execute("""
        SELECT id, name, account_status
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    if not user:
        connection.close()
        flash("User not found.")
        return redirect(url_for("admin_users"))

    if user["account_status"] == "Blocked":

        connection.execute("""
            UPDATE users
            SET account_status = 'Active'
            WHERE id = ?
        """, (user_id,))

        message = f"{user['name']} has been unblocked."

    else:

        connection.execute("""
            UPDATE users
            SET account_status = 'Blocked'
            WHERE id = ?
        """, (user_id,))

        message = f"{user['name']} has been blocked."

    connection.commit()
    connection.close()

    flash(message)

    return redirect(url_for("admin_users"))

# ==============================
# DELETE USER
# ==============================

@app.route("/admin-user-delete/<int:user_id>", methods=["POST"])
def admin_user_delete(user_id):

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    user = connection.execute("""
        SELECT id, name, account_type
        FROM users
        WHERE id = ?
    """, (user_id,)).fetchone()

    if not user:
        connection.close()
        flash("User not found.")
        return redirect(url_for("admin_users"))

    # Remove company profile if this is a company
    if user["account_type"] == "company":

        connection.execute("""
            DELETE FROM company_profiles
            WHERE user_id = ?
        """, (user_id,))

    connection.execute("""
        DELETE FROM users
        WHERE id = ?
    """, (user_id,))

    connection.commit()
    connection.close()

    flash(
        f"User '{user['name']}' was deleted successfully."
    )

    return redirect(url_for("admin_users"))

# ==============================
# MANAGE ADDED ADMINS
# ==============================

@app.route("/admin-manage-admins")
def admin_manage_admins():

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    admins = connection.execute("""
        SELECT
            id,
            name,
            email,
            role,
            account_status,
            created_at
        FROM admins
        WHERE role != 'main_admin'
           OR role IS NULL
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return render_template(
        "admin_manage_admins.html",
        admins=admins
    )


# ==============================
# BLOCK / UNBLOCK ADDED ADMIN
# ==============================

@app.route("/admin-toggle-admin-block/<int:admin_id>", methods=["POST"])
def admin_toggle_admin_block(admin_id):

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    admin = connection.execute("""
        SELECT
            id,
            name,
            role,
            account_status
        FROM admins
        WHERE id = ?
    """, (admin_id,)).fetchone()

    if not admin:
        connection.close()
        flash("Administrator not found.")
        return redirect(url_for("admin_manage_admins"))

    # Main Admin can NEVER be blocked here
    if admin["role"] == "main_admin":
        connection.close()
        flash("The Main Admin cannot be blocked.")
        return redirect(url_for("admin_manage_admins"))

    if admin["account_status"] == "Blocked":

        connection.execute("""
            UPDATE admins
            SET account_status = 'Active'
            WHERE id = ?
        """, (admin_id,))

        message = f"{admin['name']} has been unblocked."

    else:

        connection.execute("""
            UPDATE admins
            SET account_status = 'Blocked'
            WHERE id = ?
        """, (admin_id,))

        message = f"{admin['name']} has been blocked."

    connection.commit()
    connection.close()

    flash(message)

    return redirect(url_for("admin_manage_admins"))


# ==============================
# DELETE ADDED ADMIN
# ==============================

@app.route("/admin-delete-admin/<int:admin_id>", methods=["POST"])
def admin_delete_admin(admin_id):

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    admin = connection.execute("""
        SELECT
            id,
            name,
            role
        FROM admins
        WHERE id = ?
    """, (admin_id,)).fetchone()

    if not admin:
        connection.close()
        flash("Administrator not found.")
        return redirect(url_for("admin_manage_admins"))

    # Main Admin can NEVER be deleted
    if admin["role"] == "main_admin":
        connection.close()
        flash("The Main Admin cannot be deleted.")
        return redirect(url_for("admin_manage_admins"))

    connection.execute("""
        DELETE FROM admins
        WHERE id = ?
    """, (admin_id,))

    connection.commit()
    connection.close()

    flash(
        f"Administrator '{admin['name']}' was deleted successfully."
    )

    return redirect(url_for("admin_manage_admins"))                        

# =========================================
# ADMIN APPLICATIONS
# =========================================   

@app.route("/admin-applications")
def admin_applications():

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    applications = connection.execute("""
        SELECT
            a.id,
            a.full_name,
            a.email,
            a.phone,
            a.institution,
            a.course,
            a.county,
            a.status,

            o.title AS opportunity_title,
            o.company AS company_name,
            o.opportunity_type,
            o.deadline

        FROM applications a

        JOIN opportunities o
            ON a.opportunity_id = o.id

        ORDER BY a.id DESC

    """).fetchall()

    connection.close()

    return render_template(
        "admin_applications.html",
        applications=applications
    )

# ==============================
# ADMIN DELETE OPPORTUNITY
# ==============================    

@app.route("/admin-opportunity-delete/<int:opportunity_id>", methods=["POST"])
def admin_opportunity_delete(opportunity_id):

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    opportunity = connection.execute("""
        SELECT id, title
        FROM opportunities
        WHERE id = ?
    """, (opportunity_id,)).fetchone()

    if not opportunity:
        connection.close()
        flash("Opportunity not found.")
        return redirect(url_for("admin_opportunities"))

    # Delete related application documents first
    applications = connection.execute("""
        SELECT id
        FROM applications
        WHERE opportunity_id = ?
    """, (opportunity_id,)).fetchall()

    for application in applications:

        connection.execute("""
            DELETE FROM application_documents
            WHERE application_id = ?
        """, (application["id"],))

    # Delete applications
    connection.execute("""
        DELETE FROM applications
        WHERE opportunity_id = ?
    """, (opportunity_id,))

    # Delete the opportunity
    connection.execute("""
        DELETE FROM opportunities
        WHERE id = ?
    """, (opportunity_id,))

    connection.commit()
    connection.close()

    flash(
        f"Opportunity '{opportunity['title']}' was deleted successfully."
    )

    return redirect(url_for("admin_opportunities"))

# =========================================
# MAIN ADMIN SETTINGS SECURITY CODE
# =========================================

@app.route("/admin-settings-unlock", methods=["GET", "POST"])
def admin_settings_unlock():

    # Must be logged in as an admin
    if not session.get("admin_id"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    admin = connection.execute(
        """
        SELECT *
        FROM admins
        WHERE id = ?
        """,
        (session["admin_id"],)
    ).fetchone()

    connection.close()

    if admin is None:
        session.clear()
        flash("Administrator account could not be found.")
        return redirect(url_for("admin_login"))

    # Main Admin only
    if admin["id"] != 1:
        flash("Only the Main Admin can access these settings.")
        return redirect(url_for("admin_dashboard"))

    # =========================================
    # FIRST TIME: CREATE SECURITY CODE
    # =========================================

    if not admin["security_code_hash"]:

        if request.method == "POST":

            security_code = request.form.get(
                "security_code",
                ""
            ).strip()

            confirm_code = request.form.get(
                "confirm_code",
                ""
            ).strip()

            if not security_code:
                flash("Please enter a security code.")
                return redirect(
                    url_for("admin_settings_unlock")
                )

            if len(security_code) < 6:
                flash(
                    "Security code must be at least 6 characters."
                )
                return redirect(
                    url_for("admin_settings_unlock")
                )

            if security_code != confirm_code:
                flash("Security codes do not match.")
                return redirect(
                    url_for("admin_settings_unlock")
                )

            connection = get_db()

            connection.execute(
                """
                UPDATE admins
                SET security_code_hash = ?
                WHERE id = ?
                """,
                (
                    generate_password_hash(security_code),
                    admin["id"]
                )
            )

            connection.commit()
            connection.close()

            session["admin_settings_unlocked"] = True
            session["admin_settings_unlocked_at"] = time.time()

            flash(
                "Main Admin security code created successfully."
            )

            return redirect(
                url_for("admin_settings")
            )

        return render_template(
            "admin_settings_unlock.html",
            setup=True
        )

    # =========================================
    # SECURITY CODE ALREADY EXISTS
    # =========================================

    if request.method == "POST":

        security_code = request.form.get(
            "security_code",
            ""
        ).strip()

        if not security_code:
            flash("Please enter your security code.")
            return redirect(
                url_for("admin_settings_unlock")
            )

        if check_password_hash(
            admin["security_code_hash"],
            security_code
        ):
            session["admin_settings_unlocked"] = True
            session["admin_settings_unlocked_at"] = time.time()

            return redirect(
                url_for("admin_settings")
            )

        flash("Incorrect security code.")

        return redirect(
            url_for("admin_settings_unlock")
        )

    return render_template(
        "admin_settings_unlock.html",
        setup=False
    )   

# =========================================
# ADMIN SETTINGS
# =========================================

@app.route("/admin-settings", methods=["GET", "POST"])
def admin_settings():

    # =========================================
    # ADMIN LOGIN CHECK
    # =========================================

    if not session.get("admin_id"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    # =========================================
    # LOAD ADMIN
    # =========================================

    connection = get_db()

    admin = connection.execute(
        """
        SELECT *
        FROM admins
        WHERE id = ?
        """,
        (session["admin_id"],)
    ).fetchone()

    # =========================================
    # ADMIN NOT FOUND
    # =========================================

    if admin is None:
        connection.close()
        session.clear()
        flash("Administrator account could not be found.")
        return redirect(url_for("admin_login"))

    # =========================================
    # MAIN ADMIN SETTINGS SECURITY LOCK
    # =========================================

    if admin["id"] == 1:

        unlocked_at = session.get(
            "admin_settings_unlocked_at"
        )

        # Automatically lock after 10 minutes
        if (
            not session.get("admin_settings_unlocked")
            or not unlocked_at
            or time.time() - unlocked_at >= 600
        ):

            session.pop(
                "admin_settings_unlocked",
                None
            )

            session.pop(
                "admin_settings_unlocked_at",
                None
            )

            connection.close()

            return redirect(
                url_for("admin_settings_unlock")
            )

    # =========================================
    # SETTINGS PAGE
    # =========================================

    if request.method == "POST":

        action = request.form.get(
            "action",
            ""
        ).strip()

        # =====================================
        # CHANGE NAME
        # =====================================

        if action == "change_name":

            new_name = request.form.get(
                "name",
                ""
            ).strip()

            if not new_name:

                connection.close()

                flash(
                    "Please enter your name."
                )

                return redirect(
                    url_for("admin_settings")
                )

            connection.execute(
                """
                UPDATE admins
                SET name = ?
                WHERE id = ?
                """,
                (
                    new_name,
                    admin["id"]
                )
            )

            connection.commit()

            session["admin_name"] = new_name

            connection.close()

            flash(
                "Administrator name updated successfully."
            )

            return redirect(
                url_for("admin_settings")
            )

        # =====================================
        # CHANGE EMAIL
        # =====================================

        elif action == "change_email":

            new_email = request.form.get(
                "email",
                ""
            ).strip().lower()

            password = request.form.get(
                "password",
                ""
            )

            if not new_email or not password:

                connection.close()

                flash(
                    "Please enter your new email and current password."
                )

                return redirect(
                    url_for("admin_settings")
                )

            if not check_password_hash(
                admin["password_hash"],
                password
            ):

                connection.close()

                flash(
                    "Current password is incorrect."
                )

                return redirect(
                    url_for("admin_settings")
                )

            existing_email = connection.execute(
                """
                SELECT id
                FROM admins
                WHERE email = ?
                AND id != ?
                """,
                (
                    new_email,
                    admin["id"]
                )
            ).fetchone()

            if existing_email:

                connection.close()

                flash(
                    "That email address is already being used."
                )

                return redirect(
                    url_for("admin_settings")
                )

            connection.execute(
                """
                UPDATE admins
                SET email = ?
                WHERE id = ?
                """,
                (
                    new_email,
                    admin["id"]
                )
            )

            connection.commit()

            connection.close()

            flash(
                "Administrator email updated successfully."
            )

            return redirect(
                url_for("admin_settings")
            )

        # =====================================
        # CHANGE PASSWORD
        # =====================================

        elif action == "change_password":

            current_password = request.form.get(
                "current_password",
                ""
            )

            new_password = request.form.get(
                "new_password",
                ""
            )

            confirm_password = request.form.get(
                "confirm_password",
                ""
            )

            if not current_password or not new_password:

                connection.close()

                flash(
                    "Please fill in all password fields."
                )

                return redirect(
                    url_for("admin_settings")
                )

            if not check_password_hash(
                admin["password_hash"],
                current_password
            ):

                connection.close()

                flash(
                    "Current password is incorrect."
                )

                return redirect(
                    url_for("admin_settings")
                )

            if len(new_password) < 8:

                connection.close()

                flash(
                    "New password must be at least 8 characters."
                )

                return redirect(
                    url_for("admin_settings")
                )

            if new_password != confirm_password:

                connection.close()

                flash(
                    "New passwords do not match."
                )

                return redirect(
                    url_for("admin_settings")
                )

            new_password_hash = generate_password_hash(
                new_password
            )

            connection.execute(
                """
                UPDATE admins
                SET password_hash = ?
                WHERE id = ?
                """,
                (
                    new_password_hash,
                    admin["id"]
                )
            )

            connection.commit()

            connection.close()

            flash(
                "Administrator password changed successfully."
            )

            return redirect(
                url_for("admin_settings")
            )

        # =====================================
        # CHANGE SECURITY CODE
        # =====================================

        elif action == "security_code":

            if admin["role"] != "main_admin":

                connection.close()

                flash(
                    "Only the main administrator can change the security code."
                )

                return redirect(
                    url_for("admin_settings")
                )

            security_code = request.form.get(
                "security_code",
                ""
            ).strip()

            confirm_code = request.form.get(
                "confirm_code",
                ""
            ).strip()

            if (
                len(security_code) != 4
                or not security_code.isdigit()
            ):

                connection.close()

                flash(
                    "Security code must contain exactly 4 digits."
                )

                return redirect(
                    url_for("admin_settings")
                )

            if security_code != confirm_code:

                connection.close()

                flash(
                    "Security codes do not match."
                )

                return redirect(
                    url_for("admin_settings")
                )

            security_code_hash = generate_password_hash(
                security_code
            )

            connection.execute(
                """
                UPDATE admins
                SET security_code_hash = ?
                WHERE id = ?
                """,
                (
                    security_code_hash,
                    admin["id"]
                )
            )

            connection.commit()

            connection.close()

            flash(
                "Main administrator security code updated successfully."
            )

            return redirect(
                url_for("admin_settings")
            )

        # =====================================
        # INVALID REQUEST
        # =====================================

        else:

            connection.close()

            flash(
                "Invalid settings request."
            )

            return redirect(
                url_for("admin_settings")
            )

    # =========================================
    # DISPLAY SETTINGS
    # =========================================

    connection.close()

    return render_template(
        "admin_settings.html",
        admin=admin
    )


# =========================================
# MANAGE ADMINISTRATORS
# =========================================

@app.route("/manage-administrators")
def manage_administrators():

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    current_admin = connection.execute("""
        SELECT *
        FROM admins
        WHERE id = ?
    """, (
        session["admin_id"],
    )).fetchone()

    if current_admin is None:
        connection.close()
        session.clear()
        flash("Administrator account could not be found.")
        return redirect(url_for("admin_login"))

    if current_admin["role"] != "main_admin":
        connection.close()
        flash(
            "Only the Main Administrator can manage administrators."
        )
        return redirect(url_for("admin_settings"))

    administrators = connection.execute("""
        SELECT *
        FROM admins
        ORDER BY
            CASE
                WHEN role = 'main_admin' THEN 0
                ELSE 1
            END,
            name ASC
    """).fetchall()

    connection.close()

    return render_template(
        "manage_administrators.html",
        administrators=administrators,
        current_admin=current_admin
    )

# =========================================
# ADD ADMINISTRATOR
# =========================================

@app.route("/add-administrator", methods=["GET", "POST"])
def add_administrator():

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    current_admin = connection.execute("""
        SELECT *
        FROM admins
        WHERE id = ?
    """, (
        session["admin_id"],
    )).fetchone()

    if current_admin is None:
        connection.close()
        session.clear()
        flash("Administrator account could not be found.")
        return redirect(url_for("admin_login"))

    # Only the Main Administrator can add administrators
    if current_admin["role"] != "main_admin":
        connection.close()
        flash(
            "Only the Main Administrator can add administrators."
        )
        return redirect(url_for("admin_settings"))

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            connection.close()
            flash(
                "Please fill in the administrator name, email and password."
            )
            return redirect(url_for("add_administrator"))

        if len(password) < 8:
            connection.close()
            flash(
                "Administrator password must be at least 8 characters."
            )
            return redirect(url_for("add_administrator"))

        # Check whether the email is already being used
        existing_admin = connection.execute("""
            SELECT id
            FROM admins
            WHERE email = ?
        """, (
            email,
        )).fetchone()

        if existing_admin:
            connection.close()
            flash(
                "An administrator with that email already exists."
            )
            return redirect(url_for("add_administrator"))

        password_hash = generate_password_hash(password)

        connection.execute("""
            INSERT INTO admins (
                name,
                email,
                password_hash,
                role,
                security_code_hash,
                profile_photo,
                can_manage_companies,
                can_manage_opportunities,
                can_manage_applications,
                can_view_users,
                can_manage_business_ideas,
                can_view_reports
            )
            VALUES (?, ?, ?, 'admin', NULL, NULL, 0, 0, 0, 0, 0, 0)
        """, (
            name,
            email,
            password_hash
        ))

        connection.commit()
        connection.close()

        flash(
            "Administrator account created successfully."
        )

        return redirect(
            url_for("manage_administrators")
        )

    connection.close()

    return render_template(
        "add_administrator.html"
    )    

# =========================================
# ADMIN - MANAGE COMPANIES
# =========================================

@app.route("/admin-companies")
def admin_companies():

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    companies = connection.execute("""
        SELECT
            cp.id,
            cp.user_id,
            cp.company_name,
            cp.contact_person,
            cp.phone,
            cp.location,
            cp.verification_status,
            cp.submitted_at,
            cp.verified_at,
            u.email
        FROM company_profiles cp
        JOIN users u
            ON cp.user_id = u.id
        ORDER BY cp.submitted_at DESC
    """).fetchall()

    connection.close()

    return render_template(
        "admin_companies.html",
        companies=companies
    )

# =========================================
# ADMIN - VIEW / MANAGE ONE COMPANY
# =========================================

@app.route("/admin-company/<int:company_id>")
def admin_company(company_id):

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    company = connection.execute("""
        SELECT
            cp.id,
            cp.user_id,
            cp.company_name,
            cp.contact_person,
            cp.phone,
            cp.location,
            cp.verification_status,
            cp.submitted_at,
            cp.verified_at,
            u.email
        FROM company_profiles cp
        JOIN users u
            ON cp.user_id = u.id
        WHERE cp.id = ?
    """, (company_id,)).fetchone()

    connection.close()

    if company is None:
        flash("Company not found.")
        return redirect(url_for("admin_companies"))

    return render_template(
        "admin_company.html",
        company=company
    )

 # =========================================
# ADMIN - VERIFY COMPANY
# =========================================

@app.route("/admin-company/<int:company_id>/verify", methods=["POST"])
def admin_verify_company(company_id):

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    company = connection.execute("""
        SELECT *
        FROM company_profiles
        WHERE id = ?
    """, (company_id,)).fetchone()

    if company is None:
        connection.close()
        flash("Company not found.")
        return redirect(url_for("admin_companies"))

    connection.execute("""
        UPDATE company_profiles
        SET verification_status = 'Verified',
            verified_at = datetime('now')
        WHERE id = ?
    """, (company_id,))

    connection.commit()
    connection.close()

    flash("Company verified successfully.")

    return redirect(url_for(
        "admin_company",
        company_id=company_id
    ))


# =========================================
# ADMIN - REJECT COMPANY
# =========================================

@app.route("/admin-company/<int:company_id>/reject", methods=["POST"])
def admin_reject_company(company_id):

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    company = connection.execute("""
        SELECT *
        FROM company_profiles
        WHERE id = ?
    """, (company_id,)).fetchone()

    if company is None:
        connection.close()
        flash("Company not found.")
        return redirect(url_for("admin_companies"))

    connection.execute("""
        UPDATE company_profiles
        SET verification_status = 'Rejected',
            verified_at = NULL
        WHERE id = ?
    """, (company_id,))

    connection.commit()
    connection.close()

    flash("Company rejected.")

    return redirect(url_for(
        "admin_company",
        company_id=company_id
    ))


# =========================================
# ADMIN - BLOCK COMPANY
# =========================================

@app.route("/admin-company/<int:company_id>/block", methods=["POST"])
def admin_block_company(company_id):

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    company = connection.execute("""
        SELECT *
        FROM company_profiles
        WHERE id = ?
    """, (company_id,)).fetchone()

    if company is None:
        connection.close()
        flash("Company not found.")
        return redirect(url_for("admin_companies"))

    connection.execute("""
        UPDATE company_profiles
        SET verification_status = 'Blocked'
        WHERE id = ?
    """, (company_id,))

    connection.commit()
    connection.close()

    flash("Company has been blocked.")

    return redirect(url_for(
        "admin_company",
        company_id=company_id
    ))


# =========================================
# ADMIN - UNBLOCK COMPANY
# =========================================

@app.route("/admin-company/<int:company_id>/unblock", methods=["POST"])
def admin_unblock_company(company_id):

    if not session.get("is_admin"):
        flash("Administrator access required.")
        return redirect(url_for("admin_login"))

    connection = get_db()

    company = connection.execute("""
        SELECT *
        FROM company_profiles
        WHERE id = ?
    """, (company_id,)).fetchone()

    if company is None:
        connection.close()
        flash("Company not found.")
        return redirect(url_for("admin_companies"))

    connection.execute("""
        UPDATE company_profiles
        SET verification_status = 'Verified',
            verified_at = COALESCE(verified_at, datetime('now'))
        WHERE id = ?
    """, (company_id,))

    connection.commit()
    connection.close()

    flash("Company has been unblocked.")

    return redirect(url_for(
        "admin_company",
        company_id=company_id
    ))         

# =========================================
# LOGOUT
# =========================================

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("home"))


# =========================================
# ADMIN LOGOUT
# =========================================

@app.route("/admin-logout")
def admin_logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("home"))    


# =========================================
# OPPORTUNITIES
# =========================================

@app.route("/opportunities")
def opportunities():

    search = request.args.get("search", "").strip()
    opportunity_type = request.args.get("type", "").strip()
    county = request.args.get("county", "").strip()

    connection = get_db()

    # =========================================
    # ACCOUNT TYPE FILTER
    # =========================================

    if session.get("account_type") == "student":
        opportunity_type = "Attachment"

    elif session.get("account_type") == "job_seeker":
        opportunity_type = "Job"

    query = """
        SELECT *
        FROM opportunities
        WHERE 1 = 1
    """

    parameters = []

    # SEARCH
    if search:

        query += """
            AND (
                title LIKE ?
                OR company LIKE ?
                OR description LIKE ?
                OR requirements LIKE ?
                OR county LIKE ?
            )
        """

        search_value = f"%{search}%"

        parameters.extend([
            search_value,
            search_value,
            search_value,
            search_value,
            search_value
        ])

    # TYPE FILTER
    if opportunity_type:

        query += """
            AND opportunity_type = ?
        """

        parameters.append(opportunity_type)

    # COUNTY FILTER
    if county:

        query += """
            AND county = ?
        """

        parameters.append(county)

    query += """
        ORDER BY created_at DESC
    """

    opportunities_list = connection.execute(
        query,
        parameters
    ).fetchall()

    connection.close()

    today = date.today().isoformat()

    return render_template(
        "opportunities.html",
        opportunities=opportunities_list,
        today=today
    )

# =========================================
# SINGLE OPPORTUNITY
# =========================================

@app.route("/opportunity/<int:opportunity_id>")
def opportunity(opportunity_id):

    connection = get_db()

    opportunity_data = connection.execute("""
        SELECT *
        FROM opportunities
        WHERE id = ?
    """, (opportunity_id,)).fetchone()

    connection.close()

    if opportunity_data is None:

        flash("Opportunity not found.")

        return redirect(url_for("opportunities"))

    today = date.today().isoformat()

    return render_template(
        "opportunity.html",
        opportunity=opportunity_data,
        today=today
    )

# =========================================
# APPLY FOR OPPORTUNITY
# =========================================

@app.route("/apply/<int:opportunity_id>", methods=["GET", "POST"])
def apply(opportunity_id):

    if "user_id" not in session:

        flash("Please login to apply for an opportunity.")

        return redirect(
            url_for("login")
        )

    if session["account_type"] not in [
        "student",
        "job_seeker"
    ]:

        flash(
            "Only students and job seekers can apply "
            "for opportunities."
        )

        return redirect(
            url_for(
                "opportunity",
                opportunity_id=opportunity_id
            )
        )

    connection = get_db()

    # =========================================
    # GET OPPORTUNITY
    # =========================================

    opportunity_data = connection.execute("""
        SELECT *
        FROM opportunities
        WHERE id = ?
    """, (
        opportunity_id,
    )).fetchone()

    if opportunity_data is None:

        connection.close()

        flash("Opportunity not found.")

        return redirect(
            url_for("opportunities")
        )

    # =========================================
    # CHECK ACCOUNT TYPE AGAINST OPPORTUNITY
    # =========================================

    if (
        session["account_type"] == "student"
        and opportunity_data["opportunity_type"] != "Attachment"
    ):

        connection.close()

        flash(
            "This opportunity is only available "
            "to job seekers."
        )

        return redirect(
            url_for(
                "opportunity",
                opportunity_id=opportunity_id
            )
        )

    if (
        session["account_type"] == "job_seeker"
        and opportunity_data["opportunity_type"] != "Job"
    ):

        connection.close()

        flash(
            "This opportunity is only available "
            "to students."
        )

        return redirect(
            url_for(
                "opportunity",
                opportunity_id=opportunity_id
            )
        )

    # =========================================
    # CHECK DEADLINE
    # =========================================

    today = date.today().isoformat()

    if (
        opportunity_data["deadline"]
        and opportunity_data["deadline"] < today
    ):

        connection.close()

        flash(
            "This opportunity has expired and is no "
            "longer accepting applications."
        )

        return redirect(
            url_for(
                "opportunity",
                opportunity_id=opportunity_id
            )
        )

    # =========================================
    # GET LOGGED-IN USER
    # =========================================

    user = connection.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (
        session["user_id"],
    )).fetchone()

    if user is None:

        connection.close()

        session.clear()

        flash("Your account could not be found.")

        return redirect(
            url_for("login")
        )

    # =========================================
    # GET USER DATABASE COLUMNS
    # =========================================

    user_columns = [
        column["name"]
        for column in connection.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]

    # =========================================
    # SAFELY GET PROFILE VALUE
    # =========================================

    def get_profile_value(*column_names):

        for column_name in column_names:

            if column_name in user_columns:

                value = user[column_name]

                if value is not None:

                    return value

        return ""

    # =========================================
    # CHECK EXISTING APPLICATION
    # =========================================

    existing_application = connection.execute("""
        SELECT *
        FROM applications
        WHERE opportunity_id = ?
        AND applicant_id = ?
    """, (
        opportunity_id,
        session["user_id"]
    )).fetchone()

    # =========================================
    # BLOCK ALREADY SUBMITTED APPLICATIONS
    # =========================================

    if (
        existing_application
        and existing_application["status"] != "Draft"
    ):

        connection.close()

        flash(
            "You have already applied for this opportunity."
        )

        return redirect(
            url_for(
                "opportunity",
                opportunity_id=opportunity_id
            )
        )

    # =========================================
    # SUBMIT PERSONAL INFORMATION
    # =========================================

    if request.method == "POST":

        full_name = request.form.get(
            "full_name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        phone = request.form.get(
            "phone",
            ""
        ).strip()

        county = request.form.get(
            "county",
            ""
        ).strip()

        town = request.form.get(
            "town",
            ""
        ).strip()

        date_of_birth = request.form.get(
            "date_of_birth",
            ""
        ).strip()

        institution = request.form.get(
            "institution",
            ""
        ).strip()

        course = request.form.get(
            "course",
            ""
        ).strip()

        education_level = request.form.get(
            "education_level",
            ""
        ).strip()

        year_of_study = request.form.get(
            "year_of_study",
            ""
        ).strip()

        graduation_year = request.form.get(
            "graduation_year",
            ""
        ).strip()

        skills = request.form.get(
            "skills",
            ""
        ).strip()

        # =========================================
        # REQUIRED FIELDS
        # =========================================

        if not full_name:

            flash("Please enter your full name.")

            connection.close()

            return redirect(
                url_for(
                    "apply",
                    opportunity_id=opportunity_id
                )
            )

        if not email:

            flash("Please enter your email address.")

            connection.close()

            return redirect(
                url_for(
                    "apply",
                    opportunity_id=opportunity_id
                )
            )

        if not phone:

            flash("Please enter your phone number.")

            connection.close()

            return redirect(
                url_for(
                    "apply",
                    opportunity_id=opportunity_id
                )
            )

        if not county:

            flash("Please select your county.")

            connection.close()

            return redirect(
                url_for(
                    "apply",
                    opportunity_id=opportunity_id
                )
            )

        if not date_of_birth:

            flash("Please enter your date of birth.")

            connection.close()

            return redirect(
                url_for(
                    "apply",
                    opportunity_id=opportunity_id
                )
            )

        if not institution:

            flash("Please enter your institution.")

            connection.close()

            return redirect(
                url_for(
                    "apply",
                    opportunity_id=opportunity_id
                )
            )

        if not course:

            flash("Please enter your course.")

            connection.close()

            return redirect(
                url_for(
                    "apply",
                    opportunity_id=opportunity_id
                )
            )

        if not education_level:

            flash(
                "Please select your education level."
            )

            connection.close()

            return redirect(
                url_for(
                    "apply",
                    opportunity_id=opportunity_id
                )
            )

        # =========================================
        # UPDATE EXISTING DRAFT
        # =========================================

        if (
            existing_application
            and existing_application["status"] == "Draft"
        ):

            connection.execute("""
                UPDATE applications
                SET
                    full_name = ?,
                    email = ?,
                    phone = ?,
                    county = ?,
                    town = ?,
                    date_of_birth = ?,
                    institution = ?,
                    course = ?,
                    education_level = ?,
                    year_of_study = ?,
                    graduation_year = ?,
                    skills = ?
                WHERE id = ?
            """, (
                full_name,
                email,
                phone,
                county,
                town,
                date_of_birth,
                institution,
                course,
                education_level,
                year_of_study,
                graduation_year,
                skills,
                existing_application["id"]
            ))

        # =========================================
        # CREATE NEW DRAFT
        # =========================================

        else:

            connection.execute("""
                INSERT INTO applications
                (
                    opportunity_id,
                    applicant_id,
                    full_name,
                    email,
                    phone,
                    county,
                    town,
                    date_of_birth,
                    institution,
                    course,
                    education_level,
                    year_of_study,
                    graduation_year,
                    skills,
                    status
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?
                )
            """, (
                opportunity_id,
                session["user_id"],
                full_name,
                email,
                phone,
                county,
                town,
                date_of_birth,
                institution,
                course,
                education_level,
                year_of_study,
                graduation_year,
                skills,
                "Draft"
            ))

        connection.commit()

        connection.close()

        flash(
            "Your information has been saved."
        )

        return redirect(
            url_for(
                "application_documents",
                opportunity_id=opportunity_id
            )
        )

    # =========================================
    # COUNTIES
    # =========================================

    counties = [
        "Nairobi",
        "Mombasa",
        "Kisumu",
        "Nakuru",
        "Kiambu",
        "Machakos",
        "Kajiado",
        "Uasin Gishu",
        "Meru",
        "Nyeri",
        "Kirinyaga",
        "Murang'a",
        "Laikipia",
        "Kericho",
        "Kakamega",
        "Bungoma",
        "Busia",
        "Homa Bay",
        "Siaya",
        "Kitui",
        "Embu",
        "Tharaka-Nithi",
        "Nyandarua",
        "Trans Nzoia",
        "Nandi",
        "Bomet",
        "Narok",
        "Turkana",
        "Garissa",
        "Wajir",
        "Mandera",
        "Isiolo",
        "Samburu",
        "Elgeyo-Marakwet",
        "West Pokot",
        "Vihiga",
        "Migori",
        "Kisii",
        "Nyamira",
        "Taita-Taveta",
        "Kwale",
        "Kilifi",
        "Lamu",
        "Tana River",
        "Marsabit",
        "Baringo"
    ]

    # =========================================
    # PREPARE APPLICATION VALUES
    # =========================================

    if existing_application:

        application_values = {
            "full_name": existing_application["full_name"] or "",
            "email": existing_application["email"] or "",
            "phone": existing_application["phone"] or "",
            "county": existing_application["county"] or "",
            "town": existing_application["town"] or "",
            "date_of_birth": (
                existing_application["date_of_birth"] or ""
            ),
            "institution": (
                existing_application["institution"] or ""
            ),
            "course": existing_application["course"] or "",
            "education_level": (
                existing_application["education_level"] or ""
            ),
            "year_of_study": (
                existing_application["year_of_study"] or ""
            ),
            "graduation_year": (
                existing_application["graduation_year"] or ""
            ),
            "skills": existing_application["skills"] or ""
        }

    else:

        application_values = {
            "full_name": get_profile_value(
                "full_name",
                "name"
            ),
            "email": get_profile_value(
                "email"
            ),
            "phone": get_profile_value(
                "phone"
            ),
            "county": get_profile_value(
                "county"
            ),
            "town": get_profile_value(
                "town"
            ),
            "date_of_birth": get_profile_value(
                "date_of_birth"
            ),
            "institution": get_profile_value(
                "institution"
            ),
            "course": get_profile_value(
                "course"
            ),
            "education_level": get_profile_value(
                "education_level"
            ),
            "year_of_study": get_profile_value(
                "year_of_study"
            ),
            "graduation_year": get_profile_value(
                "graduation_year"
            ),
            "skills": get_profile_value(
                "skills"
            )
        }

    connection.close()

    # =========================================
    # DISPLAY APPLICATION PAGE
    # =========================================

    return render_template(
        "apply.html",
        opportunity=opportunity_data,
        user=user,
        counties=counties,
        today=today,
        application=application_values
    )


# =========================================
# APPLICATION DOCUMENTS
# =========================================

@app.route(
    "/application/<int:opportunity_id>/documents",
    methods=["GET", "POST"]
)
def application_documents(opportunity_id):

    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    if session["account_type"] not in ["student", "job_seeker"]:
        flash("Only students and job seekers can apply.")
        return redirect(url_for("dashboard"))

    connection = get_db()

    opportunity_data = connection.execute("""
        SELECT *
        FROM opportunities
        WHERE id = ?
    """, (opportunity_id,)).fetchone()

    if opportunity_data is None:
        connection.close()
        flash("Opportunity not found.")
        return redirect(url_for("opportunities"))

    # CHECK DEADLINE
    today = date.today().isoformat()

    if (
        opportunity_data["deadline"]
        and opportunity_data["deadline"] < today
    ):
        connection.close()
        flash("This opportunity has expired.")
        return redirect(
            url_for(
                "opportunity",
                opportunity_id=opportunity_id
            )
        )

    # FIND CURRENT DRAFT APPLICATION
    application = connection.execute("""
        SELECT *
        FROM applications
        WHERE opportunity_id = ?
        AND applicant_id = ?
        AND status = 'Draft'
    """, (
        opportunity_id,
        session["user_id"]
    )).fetchone()

    if application is None:
        connection.close()
        flash("Please complete your application information first.")
        return redirect(
            url_for(
                "apply",
                opportunity_id=opportunity_id
            )
        )

    if request.method == "POST":

        files = {
            "CV": request.files.get("cv"),
            "Certificate": request.files.get("certificate"),
            "Transcript": request.files.get("transcript"),
            "Cover Letter": request.files.get("cover_letter"),
            "Other Document": request.files.get("other_document")
        }

        # CV IS REQUIRED
        if not files["CV"] or not files["CV"].filename:
            connection.close()
            flash("Please upload your CV.")
            return redirect(
                url_for(
                    "application_documents",
                    opportunity_id=opportunity_id
                )
            )

        for document_type, file in files.items():

            if not file or not file.filename:
                continue

            original_filename = secure_filename(file.filename)

            if not original_filename:
                connection.close()
                flash("Invalid document filename.")
                return redirect(
                    url_for(
                        "application_documents",
                        opportunity_id=opportunity_id
                    )
                )

            extension = os.path.splitext(
                original_filename
            )[1].lower().replace(".", "")

            if extension not in ALLOWED_DOCUMENT_EXTENSIONS:
                connection.close()
                flash(
                    f"{document_type} has an unsupported file type."
                )
                return redirect(
                    url_for(
                        "application_documents",
                        opportunity_id=opportunity_id
                    )
                )

            stored_filename = f"{uuid.uuid4().hex}.{extension}"

            file_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                stored_filename
            )

            file.save(file_path)

            connection.execute("""
                INSERT INTO application_documents
                (
                    application_id,
                    document_type,
                    original_filename,
                    stored_filename
                )
                VALUES (?, ?, ?, ?)
            """, (
                application["id"],
                document_type,
                original_filename,
                stored_filename
            ))

        connection.commit()
        connection.close()

        flash("Documents uploaded successfully.")

        return redirect(
            url_for(
                "application_verification",
                opportunity_id=opportunity_id
            )
        )

    # GET EXISTING DOCUMENTS
    documents = connection.execute("""
        SELECT *
        FROM application_documents
        WHERE application_id = ?
        ORDER BY uploaded_at DESC
    """, (application["id"],)).fetchall()

    connection.close()

    return render_template(
        "application_documents.html",
        opportunity=opportunity_data,
        application=application,
        documents=documents,
        today=today
    )

 # =========================================
# APPLICATION VERIFICATION
# =========================================

@app.route(
    "/application/<int:opportunity_id>/verification",
    methods=["GET", "POST"]
)
def application_verification(opportunity_id):

    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    if session["account_type"] not in ["student", "job_seeker"]:
        flash("Only students and job seekers can apply.")
        return redirect(url_for("dashboard"))

    connection = get_db()

    # GET OPPORTUNITY
    opportunity_data = connection.execute("""
        SELECT *
        FROM opportunities
        WHERE id = ?
    """, (opportunity_id,)).fetchone()

    if opportunity_data is None:
        connection.close()
        flash("Opportunity not found.")
        return redirect(url_for("opportunities"))

    # CHECK DEADLINE
    today = date.today().isoformat()

    if (
        opportunity_data["deadline"]
        and opportunity_data["deadline"] < today
    ):
        connection.close()

        flash("This opportunity has expired.")

        return redirect(
            url_for(
                "opportunity",
                opportunity_id=opportunity_id
            )
        )

    # GET CURRENT DRAFT APPLICATION
    application = connection.execute("""
        SELECT *
        FROM applications
        WHERE opportunity_id = ?
        AND applicant_id = ?
        AND status = 'Draft'
    """, (
        opportunity_id,
        session["user_id"]
    )).fetchone()

    if application is None:
        connection.close()

        flash(
            "Please complete your application information first."
        )

        return redirect(
            url_for(
                "apply",
                opportunity_id=opportunity_id
            )
        )

    # GET UPLOADED DOCUMENTS
    documents = connection.execute("""
        SELECT *
        FROM application_documents
        WHERE application_id = ?
        ORDER BY uploaded_at DESC
    """, (application["id"],)).fetchall()

    # CHECK REQUIRED CV
    cv_uploaded = connection.execute("""
        SELECT id
        FROM application_documents
        WHERE application_id = ?
        AND document_type = 'CV'
        LIMIT 1
    """, (application["id"],)).fetchone()

    if request.method == "POST":

        confirmation = request.form.get(
            "confirm_information"
        )

        if confirmation != "yes":
            connection.close()

            flash(
                "Please confirm that your application "
                "information is accurate."
            )

            return redirect(
                url_for(
                    "application_verification",
                    opportunity_id=opportunity_id
                )
            )

        if cv_uploaded is None:
            connection.close()

            flash(
                "Please upload your CV before continuing."
            )

            return redirect(
                url_for(
                    "application_documents",
                    opportunity_id=opportunity_id
                )
            )

        # Mark application as ready for review
        connection.execute("""
            UPDATE applications
            SET status = 'Verified'
            WHERE id = ?
        """, (
            application["id"],
        ))

        connection.commit()
        connection.close()

        flash(
            "Your application information has been verified."
        )

        return redirect(
            url_for(
                "application_review",
                opportunity_id=opportunity_id
            )
        )

    connection.close()

    return render_template(
        "application_verification.html",
        opportunity=opportunity_data,
        application=application,
        documents=documents,
        cv_uploaded=cv_uploaded,
        today=today
    )

# =========================================
# APPLICATION REVIEW
# =========================================

@app.route(
    "/application/<int:opportunity_id>/review",
    methods=["GET", "POST"]
)
def application_review(opportunity_id):

    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    if session["account_type"] not in ["student", "job_seeker"]:
        flash("Only students and job seekers can apply.")
        return redirect(url_for("dashboard"))

    connection = get_db()

    # GET OPPORTUNITY
    opportunity_data = connection.execute("""
        SELECT *
        FROM opportunities
        WHERE id = ?
    """, (opportunity_id,)).fetchone()

    if opportunity_data is None:
        connection.close()
        flash("Opportunity not found.")
        return redirect(url_for("opportunities"))

    # GET APPLICATION
    application = connection.execute("""
        SELECT *
        FROM applications
        WHERE opportunity_id = ?
        AND applicant_id = ?
        AND status = 'Verified'
    """, (
        opportunity_id,
        session["user_id"]
    )).fetchone()

    if application is None:
        connection.close()

        flash(
            "Please complete the verification step first."
        )

        return redirect(
            url_for(
                "application_verification",
                opportunity_id=opportunity_id
            )
        )

    # GET DOCUMENTS
    documents = connection.execute("""
        SELECT *
        FROM application_documents
        WHERE application_id = ?
        ORDER BY uploaded_at DESC
    """, (application["id"],)).fetchall()

        # =========================================
    # FINAL SUBMISSION
    # =========================================

    if request.method == "POST":

        # =====================================
        # GET COMPANY REGISTERED EMAIL
        # =====================================

        company_user = connection.execute("""
            SELECT
                users.email AS company_email
            FROM users
            JOIN opportunities
                ON opportunities.posted_by = users.id
            WHERE opportunities.id = ?
            AND users.account_type = 'company'
        """, (
            opportunity_id,
        )).fetchone()

                # =====================================
        # MARK APPLICATION AS SUBMITTED
        # =====================================

        connection.execute("""
            UPDATE applications
            SET status = 'Submitted'
            WHERE id = ?
        """, (
            application["id"],
        ))

        # =====================================
        # CREATE COMPANY NOTIFICATION
        # =====================================

        company_user_id = opportunity_data["posted_by"]

        connection.execute("""
            INSERT INTO notifications (
                user_id,
                title,
                message,
                notification_type,
                opportunity_id
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            company_user_id,
            "New Application Received",
            (
                f"{application['full_name']} has submitted "
                f"an application for {opportunity_data['title']}."
            ),
            "new_application",
            opportunity_id
        ))

        connection.commit()

        # =====================================
        # CREATE APPLICATION VIEW LINK
        # =====================================

        application_url = url_for(
            "company_applications",
            _external=True
        )

        # =====================================
        # SEND EMAIL TO COMPANY
        # =====================================

        email_sent = False

        if company_user and company_user["company_email"]:

            email_sent = send_company_application_email(
                company_email=company_user["company_email"],
                applicant_name=application["full_name"],
                opportunity_title=opportunity_data["title"],
                institution=application["institution"],
                course=application["course"],
                county=application["county"],
                applicant_email=application["email"],
                application_url=application_url
            )

        connection.close()

        # =====================================
        # SUCCESS MESSAGE
        # =====================================

        if email_sent:

            flash(
                "Your application has been submitted successfully!"
            )

        else:

            flash(
                "Your application has been submitted successfully. "
                "The company email notification could not be sent."
            )

        return redirect(
            url_for(
                "opportunity",
                opportunity_id=opportunity_id
            )
        )

    connection.close()

    return render_template(
        "application_review.html",
        opportunity=opportunity_data,
        application=application,
        documents=documents
    )

    # =========================================
# STUDENT / JOB SEEKER APPLICATIONS
# =========================================

@app.route("/my-applications")
def my_applications():

    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    if session["account_type"] not in ["student", "job_seeker"]:
        flash("Only students and job seekers can view applications.")
        return redirect(url_for("dashboard"))

    connection = get_db()

    applications = connection.execute("""
        SELECT
            applications.*,
            opportunities.title AS opportunity_title,
            opportunities.company AS company_name,
            opportunities.county AS opportunity_county,
            opportunities.opportunity_type AS opportunity_type,
            opportunities.deadline AS opportunity_deadline
        FROM applications
        JOIN opportunities
            ON applications.opportunity_id = opportunities.id
        WHERE applications.applicant_id = ?
        ORDER BY applications.applied_at DESC
    """, (
        session["user_id"],
    )).fetchall()

    connection.close()

    return render_template(
        "my_applications.html",
        applications=applications,
        today=date.today().isoformat()
    )

# =========================================
# COMPANY APPLICATIONS
# =========================================

@app.route("/company-applications")
def company_applications():

    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    if session["account_type"] != "company":
        flash("Only company accounts can access applications.")
        return redirect(url_for("dashboard"))

    connection = get_db()

    applications = connection.execute("""
        SELECT
            applications.*,
            opportunities.title AS opportunity_title,
            opportunities.company AS company_name,
            opportunities.opportunity_type AS opportunity_type,
            users.name AS applicant_name,
            users.email AS applicant_account_email
        FROM applications
        JOIN opportunities
            ON applications.opportunity_id = opportunities.id
        JOIN users
            ON applications.applicant_id = users.id
        WHERE opportunities.posted_by = ?
        AND applications.status != 'Draft'
        ORDER BY applications.applied_at DESC
    """, (
        session["user_id"],
    )).fetchall()

    connection.close()

    job_applications = []
    student_applications = []

    for application in applications:

        if application["opportunity_type"] == "Job":
            job_applications.append(application)

        elif application["opportunity_type"] in [
            "Attachment",
            "Internship"
        ]:
            student_applications.append(application)

    return render_template(
        "company_applications.html",
        applications=applications,
        job_applications=job_applications,
        student_applications=student_applications,
        job_application_count=len(job_applications),
        student_application_count=len(student_applications),
        total_application_count=len(applications)
    )


# =========================================
# COMPANY JOB APPLICATIONS
# =========================================

@app.route("/company-job-applications")
def company_job_applications():

    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    if session["account_type"] != "company":
        flash("Only company accounts can access applications.")
        return redirect(url_for("dashboard"))

    connection = get_db()

    applications = connection.execute("""
        SELECT
            applications.*,
            opportunities.title AS opportunity_title,
            opportunities.company AS company_name,
            opportunities.opportunity_type AS opportunity_type,
            users.name AS applicant_name,
            users.email AS applicant_account_email
        FROM applications
        JOIN opportunities
            ON applications.opportunity_id = opportunities.id
        JOIN users
            ON applications.applicant_id = users.id
        WHERE opportunities.posted_by = ?
        AND opportunities.opportunity_type = 'Job'
        AND applications.status != 'Draft'
        ORDER BY applications.applied_at DESC
    """, (
        session["user_id"],
    )).fetchall()

    connection.close()

    return render_template(
        "company_application_list.html",
        applications=applications,
        page_title="Job Applications",
        page_icon="💼",
        page_description="Applications submitted for your job opportunities."
    )


# =========================================
# COMPANY ATTACHMENT / INTERNSHIP APPLICATIONS
# =========================================

@app.route("/company-student-applications")
def company_student_applications():

    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    if session["account_type"] != "company":
        flash("Only company accounts can access applications.")
        return redirect(url_for("dashboard"))

    connection = get_db()

    applications = connection.execute("""
        SELECT
            applications.*,
            opportunities.title AS opportunity_title,
            opportunities.company AS company_name,
            opportunities.opportunity_type AS opportunity_type,
            users.name AS applicant_name,
            users.email AS applicant_account_email
        FROM applications
        JOIN opportunities
            ON applications.opportunity_id = opportunities.id
        JOIN users
            ON applications.applicant_id = users.id
        WHERE opportunities.posted_by = ?
        AND opportunities.opportunity_type IN ('Attachment', 'Internship')
        AND applications.status != 'Draft'
        ORDER BY applications.applied_at DESC
    """, (
        session["user_id"],
    )).fetchall()

    connection.close()

    return render_template(
        "company_application_list.html",
        applications=applications,
        page_title="Attachment / Internship Applications",
        page_icon="🎓",
        page_description="Applications submitted for your student opportunities."
    )


# =========================================
# ALL COMPANY APPLICATIONS
# =========================================

@app.route("/company-all-applications")
def company_all_applications():

    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    if session["account_type"] != "company":
        flash("Only company accounts can access applications.")
        return redirect(url_for("dashboard"))

    connection = get_db()

    applications = connection.execute("""
        SELECT
            applications.*,
            opportunities.title AS opportunity_title,
            opportunities.company AS company_name,
            opportunities.opportunity_type AS opportunity_type,
            users.name AS applicant_name,
            users.email AS applicant_account_email
        FROM applications
        JOIN opportunities
            ON applications.opportunity_id = opportunities.id
        JOIN users
            ON applications.applicant_id = users.id
        WHERE opportunities.posted_by = ?
        AND applications.status != 'Draft'
        ORDER BY applications.applied_at DESC
    """, (
        session["user_id"],
    )).fetchall()

    connection.close()

    return render_template(
        "company_application_list.html",
        applications=applications,
        page_title="All Applications",
        page_icon="📊",
        page_description="All applications submitted for your opportunities."
    )


# =========================================
# COMPANY VIEW APPLICATION
# =========================================

@app.route(
    "/company-application/<int:application_id>"
)
def company_application(application_id):

    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    if session["account_type"] != "company":
        flash("Only company accounts can view applications.")
        return redirect(url_for("dashboard"))

    connection = get_db()

    application = connection.execute("""
        SELECT
            applications.*,

            opportunities.title AS opportunity_title,
            opportunities.company AS company_name,
            opportunities.posted_by,

            users.name AS applicant_account_name,
            users.email AS applicant_account_email

        FROM applications

        JOIN opportunities
            ON applications.opportunity_id = opportunities.id

        JOIN users
            ON applications.applicant_id = users.id

        WHERE applications.id = ?
        AND opportunities.posted_by = ?
    """, (
        application_id,
        session["user_id"]
    )).fetchone()

    if application is None:
        connection.close()

        flash(
            "Application not found or you do not have permission "
            "to view it."
        )

        return redirect(
            url_for("company_applications")
        )

    documents = connection.execute("""
        SELECT *
        FROM application_documents
        WHERE application_id = ?
        ORDER BY uploaded_at DESC
    """, (
        application_id,
    )).fetchall()

    connection.close()

    return render_template(
        "company_application.html",
        application=application,
        documents=documents
    )


# =========================================
# COMPANY UPDATE APPLICATION STATUS
# =========================================

@app.route(
    "/company-application/<int:application_id>/status",
    methods=["POST"]
)
def company_update_application_status(application_id):

    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    if session["account_type"] != "company":
        flash("Only company accounts can update applications.")
        return redirect(url_for("dashboard"))

    new_status = request.form.get(
        "status",
        ""
    ).strip()

    allowed_statuses = {
        "Under Review",
        "Shortlisted",
        "Rejected",
        "Accepted"
    }

    if new_status not in allowed_statuses:
        flash("Invalid application status.")
        return redirect(
            url_for(
                "company_application",
                application_id=application_id
            )
        )

    connection = get_db()

    # Make sure this application belongs
    # to an opportunity owned by the company.
    application = connection.execute("""
        SELECT
            applications.id,
            applications.opportunity_id
        FROM applications

        JOIN opportunities
            ON applications.opportunity_id = opportunities.id

        WHERE applications.id = ?
        AND opportunities.posted_by = ?
    """, (
        application_id,
        session["user_id"]
    )).fetchone()

    if application is None:
        connection.close()

        flash(
            "Application not found or you do not have permission "
            "to update it."
        )

        return redirect(
            url_for("company_applications")
        )

    connection.execute("""
        UPDATE applications
        SET status = ?
        WHERE id = ?
    """, (
        new_status,
        application_id
    ))

    connection.commit()
    connection.close()

    flash(
        f"Application status updated to {new_status}."
    )

    return redirect(
        url_for(
            "company_application",
            application_id=application_id
        )
    )


# =========================================
# COMPANY DOWNLOAD APPLICATION DOCUMENT
# =========================================

@app.route(
    "/company-application-document/<int:document_id>"
)
def company_application_document(document_id):

    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    if session["account_type"] != "company":
        flash("Only companies can access applicant documents.")
        return redirect(url_for("dashboard"))

    connection = get_db()

    document = connection.execute("""
        SELECT
            application_documents.*,
            opportunities.posted_by

        FROM application_documents

        JOIN applications
            ON application_documents.application_id =
               applications.id

        JOIN opportunities
            ON applications.opportunity_id =
               opportunities.id

        WHERE application_documents.id = ?
        AND opportunities.posted_by = ?
    """, (
        document_id,
        session["user_id"]
    )).fetchone()

    connection.close()

    if document is None:
        abort(404)

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        document["stored_filename"]
    )

    if not os.path.isfile(file_path):
        abort(404)

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        document["stored_filename"],
        as_attachment=True,
        download_name=document["original_filename"]
    )


# =========================================
# COMPANY DASHBOARD
# =========================================

@app.route("/company-dashboard")
def company_dashboard():

    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    if session["account_type"] != "company":
        flash("Only company accounts can access this page.")
        return redirect(url_for("dashboard"))

    connection = get_db()

    # Get this company's opportunities
    company_opportunities = connection.execute("""
        SELECT *
        FROM opportunities
        WHERE posted_by = ?
        ORDER BY created_at DESC
    """, (
        session["user_id"],
    )).fetchall()

    # Count submitted/non-draft applications
    application_count = connection.execute("""
        SELECT COUNT(*)
        FROM applications
        JOIN opportunities
            ON applications.opportunity_id = opportunities.id
        WHERE opportunities.posted_by = ?
        AND applications.status != 'Draft'
    """, (
        session["user_id"],
    )).fetchone()[0]

    # Count active listings
    active_listing_count = connection.execute("""
        SELECT COUNT(*)
        FROM opportunities
        WHERE posted_by = ?
        AND (
            deadline IS NULL
            OR deadline >= ?
        )
    """, (
        session["user_id"],
        date.today().isoformat()
    )).fetchone()[0]

    connection.close()

    return render_template(
        "company_dashboard.html",
        opportunities=company_opportunities,
        application_count=application_count,
        active_listing_count=active_listing_count
    )

# =========================================
# COMPANY SETTINGS
# =========================================

@app.route("/company-settings", methods=["GET", "POST"])
def company_settings():

    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    if session.get("account_type") != "company":
        flash("Only company accounts can access settings.")
        return redirect(url_for("dashboard"))

    connection = get_db()

    # =====================================
    # GET CURRENT COMPANY PROFILE
    # =====================================

    company_profile = connection.execute(
        """
        SELECT *
        FROM company_profiles
        WHERE user_id = ?
        """,
        (session["user_id"],)
    ).fetchone()

    # =====================================
    # HANDLE FORM SUBMISSION
    # =====================================

    if request.method == "POST":

        form_type = request.form.get(
            "form_type",
            ""
        ).strip()

        # =====================================
        # SAVE COMPANY PROFILE
        # =====================================

        if form_type == "profile":

            company_name = request.form.get(
                "company_name",
                ""
            ).strip()

            contact_person = request.form.get(
                "contact_person",
                ""
            ).strip()

            phone = request.form.get(
                "phone",
                ""
            ).strip()

            location = request.form.get(
                "location",
                ""
            ).strip()

            # ---------------------------------
            # VALIDATE PROFILE
            # ---------------------------------

            if not company_name:
                connection.close()
                flash("Please enter the company name.")
                return redirect(
                    url_for("company_settings")
                )

            if not contact_person:
                connection.close()
                flash("Please enter the contact person's name.")
                return redirect(
                    url_for("company_settings")
                )

            if not phone:
                connection.close()
                flash("Please enter the phone number.")
                return redirect(
                    url_for("company_settings")
                )

            if not location:
                connection.close()
                flash("Please enter the company location.")
                return redirect(
                    url_for("company_settings")
                )

            # ---------------------------------
            # UPDATE EXISTING PROFILE
            # ---------------------------------

            if company_profile:

                connection.execute(
                    """
                    UPDATE company_profiles
                    SET
                        company_name = ?,
                        contact_person = ?,
                        phone = ?,
                        location = ?
                    WHERE user_id = ?
                    """,
                    (
                        company_name,
                        contact_person,
                        phone,
                        location,
                        session["user_id"]
                    )
                )

                connection.commit()

                # Confirm the saved information
                updated_profile = connection.execute(
                    """
                    SELECT *
                    FROM company_profiles
                    WHERE user_id = ?
                    """,
                    (session["user_id"],)
                ).fetchone()

                connection.close()

                if updated_profile:
                    flash(
                        "Company profile updated successfully!"
                    )
                else:
                    flash(
                        "Profile could not be verified after saving."
                    )

                return redirect(
                    url_for("company_settings")
                )

            # ---------------------------------
            # CREATE PROFILE IF NONE EXISTS
            # ---------------------------------

            connection.execute(
                """
                INSERT INTO company_profiles (
                    user_id,
                    company_name,
                    contact_person,
                    phone,
                    location
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    session["user_id"],
                    company_name,
                    contact_person,
                    phone,
                    location
                )
            )

            connection.commit()

            connection.close()

            flash(
                "Company profile saved successfully!"
            )

            return redirect(
                url_for("company_settings")
            )

                # =====================================
        # CHANGE PASSWORD
        # =====================================

        if form_type == "password":

            current_password = request.form.get(
                "current_password",
                ""
            )

            new_password = request.form.get(
                "new_password",
                ""
            )

            user = connection.execute(
                """
                SELECT id, password_hash
                FROM users
                WHERE id = ?
                """,
                (session["user_id"],)
            ).fetchone()

            if not user:

                connection.close()

                flash(
                    "Account could not be found."
                )

                return redirect(
                    url_for("company_settings")
                )

            # =================================
            # CHECK CURRENT PASSWORD
            # =================================

            if not check_password_hash(
                user["password_hash"],
                current_password
            ):

                connection.close()

                flash(
                    "Current password is incorrect."
                )

                return redirect(
                    url_for("company_settings")
                )

            # =================================
            # CHECK NEW PASSWORD
            # =================================

            if len(new_password) < 8:

                connection.close()

                flash(
                    "New password must be at least 8 characters."
                )

                return redirect(
                    url_for("company_settings")
                )

            # =================================
            # CREATE NEW PASSWORD HASH
            # =================================

            new_password_hash = generate_password_hash(
                new_password
            )

            # =================================
            # SAVE NEW PASSWORD
            # =================================

            connection.execute(
                """
                UPDATE users
                SET password_hash = ?
                WHERE id = ?
                """,
                (
                    new_password_hash,
                    session["user_id"]
                )
            )

            connection.commit()

            connection.close()

            flash(
                "Password updated successfully!"
            )

            return redirect(
                url_for("company_settings")
            )

    # =====================================
    # DISPLAY SETTINGS PAGE
    # =====================================

    connection.close()

    return render_template(
        "company_settings.html",
        company_profile=company_profile
    )


# =========================================
# POST OPPORTUNITY
# =========================================

@app.route("/post-opportunity", methods=["GET", "POST"])
def post_opportunity():

    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    if session.get("account_type") != "company":
        flash("Only companies can post opportunities.")
        return redirect(url_for("dashboard"))

    connection = get_db()

    columns = connection.execute(
        "PRAGMA table_info(opportunities)"
    ).fetchall()

    column_names = [column["name"] for column in columns]

    if "positions_available" not in column_names:

        connection.execute(
            """
            ALTER TABLE opportunities
            ADD COLUMN positions_available INTEGER DEFAULT 1
            """
        )

        connection.commit()

    if "audience" not in column_names:

        connection.execute(
            """
            ALTER TABLE opportunities
            ADD COLUMN audience TEXT DEFAULT 'student'
            """
        )

        connection.commit()

    if request.method == "POST":

        title = request.form.get("title", "").strip()

        opportunity_type = request.form.get(
            "opportunity_type", ""
        ).strip()

        company = request.form.get(
            "company", ""
        ).strip()

        county = request.form.get(
            "county", ""
        ).strip()

        course = request.form.get(
            "course", ""
        ).strip()

        industry = request.form.get(
            "industry", ""
        ).strip()

        description = request.form.get(
            "description", ""
        ).strip()

        requirements = request.form.get(
            "requirements", ""
        ).strip()

        deadline = request.form.get(
            "deadline", ""
        ).strip()

        contact_email = request.form.get(
            "contact_email", ""
        ).strip()

        audience = request.form.get(
            "audience", ""
        ).strip()

        positions_value = request.form.get(
            "positions_available", "1"
        ).strip()

        try:

            positions_available = int(
                positions_value
            )

        except (ValueError, TypeError):

            positions_available = 1

        if positions_available < 1:

            positions_available = 1

        if (
            not title
            or not opportunity_type
            or not company
            or not county
            or not description
            or not audience
        ):

            flash(
                "Please fill in all required fields."
            )

            connection.close()

            return redirect(
                url_for("post_opportunity")
            )

        if (
            opportunity_type == "Job"
            and audience != "job_seeker"
        ):

            flash(
                "Job opportunities must be posted for Job Seekers."
            )

            connection.close()

            return redirect(
                url_for("post_opportunity")
            )

        if (
            opportunity_type in ["Attachment", "Internship"]
            and audience != "student"
        ):

            flash(
                "Attachment and Internship opportunities must be posted for Students."
            )

            connection.close()

            return redirect(
                url_for("post_opportunity")
            )

                # =========================================
        # INSERT OPPORTUNITY
        # =========================================

        cursor = connection.execute(
            """
            INSERT INTO opportunities (
                title,
                opportunity_type,
                company,
                county,
                course,
                industry,
                description,
                requirements,
                deadline,
                contact_email,
                positions_available,
                audience,
                posted_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                opportunity_type,
                company,
                county,
                course,
                industry,
                description,
                requirements,
                deadline,
                contact_email,
                positions_available,
                audience,
                session["user_id"]
            )
        )

        opportunity_id = cursor.lastrowid

        # =========================================
        # CREATE NOTIFICATIONS FOR USERS
        # =========================================

        if audience == "student":

            recipients = connection.execute(
                """
                SELECT id
                FROM users
                WHERE account_type = 'student'
                AND account_status = 'Active'
                """
            ).fetchall()

        elif audience == "job_seeker":

            recipients = connection.execute(
                """
                SELECT id
                FROM users
                WHERE account_type = 'job_seeker'
                AND account_status = 'Active'
                """
            ).fetchall()

        else:

            recipients = []

        notification_title = (
            f"New {opportunity_type} Opportunity"
        )

        notification_message = (
            f"{company} has posted a new "
            f"{opportunity_type.lower()} opportunity: "
            f"{title}"
        )

        for recipient in recipients:

            connection.execute(
                """
                INSERT INTO notifications (
                    user_id,
                    title,
                    message,
                    notification_type,
                    opportunity_id
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    recipient["id"],
                    notification_title,
                    notification_message,
                    "new_opportunity",
                    opportunity_id
                )
            )

        # =========================================
        # NOTIFY THE COMPANY THAT POSTED
        # =========================================

        connection.execute(
            """
            INSERT INTO notifications (
                user_id,
                title,
                message,
                notification_type,
                opportunity_id
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                session["user_id"],
                "Opportunity Posted",
                f"Your opportunity '{title}' has been posted successfully.",
                "opportunity_posted",
                opportunity_id
            )
        )

        # =========================================
        # SAVE DATABASE CHANGES
        # =========================================

        connection.commit()

        connection.close()

        flash(
            "Opportunity posted successfully!"
        )

        return redirect(
            url_for("company_dashboard")
        )

    connection.close()

    return render_template(
        "post_opportunity.html"
    )

# =========================================
# EDIT OPPORTUNITY
# =========================================

@app.route("/edit-opportunity/<int:opportunity_id>", methods=["GET", "POST"])
def edit_opportunity(opportunity_id):

    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    if session["account_type"] != "company":
        flash("Only company accounts can edit opportunities.")
        return redirect(url_for("dashboard"))

    connection = get_db()

    opportunity_data = connection.execute("""
        SELECT *
        FROM opportunities
        WHERE id = ?
        AND posted_by = ?
    """, (
        opportunity_id,
        session["user_id"]
    )).fetchone()

    if opportunity_data is None:
        connection.close()

        flash("Opportunity not found or you do not have permission to edit it.")
        return redirect(url_for("company_dashboard"))

    if request.method == "POST":

        title = request.form["title"]
        opportunity_type = request.form["opportunity_type"]
        county = request.form["county"]
        description = request.form["description"]
        requirements = request.form["requirements"]
        deadline = request.form["deadline"]
        contact_email = request.form["contact_email"]

        connection.execute("""
            UPDATE opportunities
            SET
                title = ?,
                opportunity_type = ?,
                county = ?,
                description = ?,
                requirements = ?,
                deadline = ?,
                contact_email = ?
            WHERE id = ?
            AND posted_by = ?
        """, (
            title,
            opportunity_type,
            county,
            description,
            requirements,
            deadline,
            contact_email,
            opportunity_id,
            session["user_id"]
        ))

        connection.commit()
        connection.close()

        flash("Opportunity updated successfully.")

        return redirect(url_for("company_dashboard"))

    connection.close()

    return render_template(
        "edit_opportunity.html",
        opportunity=opportunity_data
    )


# =========================================
# DELETE OPPORTUNITY
# =========================================

@app.route(
    "/delete-opportunity/<int:opportunity_id>",
    methods=["POST"]
)
def delete_opportunity(opportunity_id):

    # Must be logged in
    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    # Only companies can delete opportunities
    if session["account_type"] != "company":
        flash("Only company accounts can remove opportunities.")
        return redirect(url_for("dashboard"))

    connection = get_db()

    # Make sure the opportunity belongs to the logged-in company
    opportunity_data = connection.execute("""
        SELECT *
        FROM opportunities
        WHERE id = ?
        AND posted_by = ?
    """, (
        opportunity_id,
        session["user_id"]
    )).fetchone()

    if opportunity_data is None:
        connection.close()

        flash(
            "Opportunity not found or you do not have permission "
            "to remove it."
        )

        return redirect(url_for("company_dashboard"))

    # Delete related application documents first
    connection.execute("""
        DELETE FROM application_documents
        WHERE application_id IN (
            SELECT id
            FROM applications
            WHERE opportunity_id = ?
        )
    """, (opportunity_id,))

    # Delete applications
    connection.execute("""
        DELETE FROM applications
        WHERE opportunity_id = ?
    """, (opportunity_id,))

    # Delete the opportunity
    connection.execute("""
        DELETE FROM opportunities
        WHERE id = ?
        AND posted_by = ?
    """, (
        opportunity_id,
        session["user_id"]
    ))

    connection.commit()
    connection.close()

    flash("Opportunity removed successfully.")

    return redirect(url_for("company_dashboard"))


# =========================================
# PROFILE
# =========================================

@app.route("/profile", methods=["GET", "POST"])
def profile():

    if "user_id" not in session:

        flash("Please login first.")

        return redirect(
            url_for("login")
        )

    connection = get_db()

    # =========================================
    # GET USER
    # =========================================

    user = connection.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (
        session["user_id"],
    )).fetchone()

    if not user:

        connection.close()

        session.clear()

        flash("Your account could not be found.")

        return redirect(
            url_for("login")
        )

    # =========================================
    # GET AVAILABLE USER COLUMNS
    # =========================================

    user_columns = [
        column["name"]
        for column in connection.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]

    # =========================================
    # GET USER VALUE
    # =========================================

    def get_user_value(column_name, default=""):

        if column_name in user_columns:

            value = user[column_name]

            if value is not None:

                return value

        return default

    # =========================================
    # SAVE PROFILE
    # =========================================

    if request.method == "POST":

        # -----------------------------------------
        # GET FORM VALUES
        # -----------------------------------------

        full_name = request.form.get(
            "full_name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        phone = request.form.get(
            "phone",
            ""
        ).strip()

        county = request.form.get(
            "county",
            ""
        ).strip()

        town = request.form.get(
            "town",
            ""
        ).strip()

        date_of_birth = request.form.get(
            "date_of_birth",
            ""
        ).strip()

        institution = request.form.get(
            "institution",
            ""
        ).strip()

        course = request.form.get(
            "course",
            ""
        ).strip()

        education_level = request.form.get(
            "education_level",
            ""
        ).strip()

        year_of_study = request.form.get(
            "year_of_study",
            ""
        ).strip()

        graduation_year = request.form.get(
            "graduation_year",
            ""
        ).strip()

        skills = request.form.get(
            "skills",
            ""
        ).strip()

        # =========================================
        # REQUIRED INFORMATION
        # =========================================

        if not full_name:

            connection.close()

            flash(
                "Please enter your full name."
            )

            return redirect(
                url_for("profile")
            )

        if not email:

            connection.close()

            flash(
                "Please enter your email address."
            )

            return redirect(
                url_for("profile")
            )

        # =========================================
        # CHECK EMAIL
        # =========================================

        if "email" in user_columns:

            existing_email = connection.execute("""
                SELECT id
                FROM users
                WHERE LOWER(email) = ?
                AND id != ?
            """, (
                email,
                session["user_id"],
            )).fetchone()

            if existing_email:

                connection.close()

                flash(
                    "That email address is already being used."
                )

                return redirect(
                    url_for("profile")
                )

        # =========================================
        # PREPARE PROFILE DATA
        # =========================================

        profile_values = {
            "full_name": full_name,
            "email": email,
            "phone": phone,
            "county": county,
            "town": town,
            "date_of_birth": date_of_birth,
            "institution": institution,
            "course": course,
            "education_level": education_level,
            "year_of_study": year_of_study,
            "graduation_year": graduation_year,
            "skills": skills
        }

        # =========================================
        # UPDATE EXISTING COLUMNS
        # =========================================

        update_parts = []

        update_values = []

        for column_name, value in profile_values.items():

            if column_name in user_columns:

                update_parts.append(
                    f"{column_name} = ?"
                )

                update_values.append(value)

        # =========================================
        # IMPORTANT:
        # SUPPORT EXISTING "name" COLUMN
        # =========================================

        if (
            "full_name" not in user_columns
            and "name" in user_columns
        ):

            update_parts.append(
                "name = ?"
            )

            update_values.append(
                full_name
            )

        # =========================================
        # UPDATE USER
        # =========================================

        if update_parts:

            update_values.append(
                session["user_id"]
            )

            connection.execute(
                f"""
                UPDATE users
                SET {", ".join(update_parts)}
                WHERE id = ?
                """,
                tuple(update_values)
            )

            connection.commit()

        # =========================================
        # GET UPDATED USER
        # =========================================

        user = connection.execute("""
            SELECT *
            FROM users
            WHERE id = ?
        """, (
            session["user_id"],
        )).fetchone()

        # =========================================
        # REFRESH PROFILE VALUES
        # =========================================

        def get_updated_value(
            primary_column,
            fallback_column=None
        ):

            if primary_column in user_columns:

                value = user[primary_column]

                if value is not None:
                    return value

            if (
                fallback_column
                and fallback_column in user_columns
            ):

                value = user[fallback_column]

                if value is not None:
                    return value

            return ""

        profile_data = {
            "full_name": get_updated_value(
                "full_name",
                "name"
            ),
            "email": get_updated_value(
                "email"
            ),
            "phone": get_updated_value(
                "phone"
            ),
            "county": get_updated_value(
                "county"
            ),
            "town": get_updated_value(
                "town"
            ),
            "date_of_birth": get_updated_value(
                "date_of_birth"
            ),
            "institution": get_updated_value(
                "institution"
            ),
            "course": get_updated_value(
                "course"
            ),
            "education_level": get_updated_value(
                "education_level"
            ),
            "year_of_study": get_updated_value(
                "year_of_study"
            ),
            "graduation_year": get_updated_value(
                "graduation_year"
            ),
            "skills": get_updated_value(
                "skills"
            )
        }

        connection.close()

        flash(
            "Your profile has been updated successfully."
        )

        return render_template(
            "profile.html",
            user=user,
            profile=profile_data,
            name=profile_data["full_name"] or "User",
            account_type=get_updated_value(
                "account_type"
            ) or "student"
        )

    # =========================================
    # PREPARE PROFILE FOR GET REQUEST
    # =========================================

    profile_data = {
        "full_name": get_user_value(
            "full_name",
            get_user_value("name")
        ),
        "email": get_user_value("email"),
        "phone": get_user_value("phone"),
        "county": get_user_value("county"),
        "town": get_user_value("town"),
        "date_of_birth": get_user_value("date_of_birth"),
        "institution": get_user_value("institution"),
        "course": get_user_value("course"),
        "education_level": get_user_value(
            "education_level"
        ),
        "year_of_study": get_user_value(
            "year_of_study"
        ),
        "graduation_year": get_user_value(
            "graduation_year"
        ),
        "skills": get_user_value("skills")
    }

    connection.close()

    # =========================================
    # DISPLAY PROFILE
    # =========================================

    return render_template(
        "profile.html",
        user=user,
        profile=profile_data,
        name=profile_data["full_name"] or "User",
        account_type=get_user_value(
            "account_type"
        ) or "student"
    )
    
# =========================================
# SETTINGS
# =========================================

@app.route("/settings")
def settings():

    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login"))

    return render_template("settings.html")

# =========================================
# TEMPORARY ADMIN PASSWORD RESET
# =========================================

@app.route("/reset-admin", methods=["GET", "POST"])
@csrf.exempt
def reset_admin():

    connection = get_db()

    admin = connection.execute("""
        SELECT id, name, email
        FROM admins
        LIMIT 1
    """).fetchone()

    if admin is None:
        connection.close()
        return "No admin account exists."

    if request.method == "POST":

        new_password = request.form.get("password", "")

        if len(new_password) < 8:
            connection.close()
            return "Password must be at least 8 characters."

        new_password_hash = generate_password_hash(new_password)

        connection.execute("""
            UPDATE admins
            SET password_hash = ?
            WHERE id = ?
        """, (
            new_password_hash,
            admin["id"]
        ))

        connection.commit()
        connection.close()

        return f"""
        <h2>Admin password reset successfully.</h2>
        <p>Admin email: {admin["email"]}</p>
        <p>You can now login using your new password.</p>
        """

    connection.close()

    return """
    <h2>Reset Admin Password</h2>

    <form method="POST">

        <label>New Password:</label><br>

        <input
            type="password"
            name="password"
            minlength="8"
            required
        >

        <br><br>

        <button type="submit">
            Reset Password
        </button>

    </form>
    """


# =========================================
# START APPLICATION
# =========================================

create_database()

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )