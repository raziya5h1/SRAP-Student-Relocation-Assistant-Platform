# app.py
import os
import json
import uuid
import random
import requests
import pandas as pd
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, jsonify, Markup, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from geopy.geocoders import Nominatim
import math
from functools import wraps
from flask import session, flash, redirect, url_for, request, render_template

# -------------------------
# Paths & Excel
# -------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Subfolder specifically for profile pictures
PROFILE_PIC_FOLDER = os.path.join(UPLOAD_FOLDER, "profile_pics")
os.makedirs(PROFILE_PIC_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"png","jpg","jpeg","gif","pdf","doc","docx","txt"}

def allowed_file(filename:str):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

excel_path = os.path.join(BASE_DIR, "data", "doc_requirements.xlsx")
try:
    college_data = pd.read_excel(excel_path)
    college_data.columns = college_data.columns.str.strip()
    if 'College Name' in college_data.columns:
        college_data.rename(columns={'College Name':'College'}, inplace=True)
except:
    college_data = pd.DataFrame(columns=["College","Document_Name"])

# -------------------------
# Load environment variables
# -------------------------
load_dotenv(os.path.join(BASE_DIR, ".env"))

# -------------------------
# Flask App Config
# -------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY","dev-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL","sqlite:///srap.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 50*1024*1024
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# -------------------------
# Init DB & Mail
# -------------------------
db = SQLAlchemy(app)

app.config.update(
    MAIL_SERVER=os.getenv("MAIL_SERVER","smtp.gmail.com"),
    MAIL_PORT=int(os.getenv("MAIL_PORT",587)),
    MAIL_USE_TLS=os.getenv("MAIL_USE_TLS","true").lower()=="true",
    MAIL_USE_SSL=os.getenv("MAIL_USE_SSL","false").lower()=="true",
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_DEFAULT_SENDER=os.getenv("MAIL_DEFAULT_SENDER")
)
mail = Mail(app)

# -------------------------
# Database Models
# -------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    college = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(20), nullable=False)
    branch = db.Column(db.String(60), nullable=False)
    sem = db.Column(db.String(20), nullable=False)
    roll = db.Column(db.String(60), nullable=False)
    password = db.Column(db.String(255), nullable=False)

    # New fields for profile picture
    profile_pic = db.Column(db.String(255), nullable=True)  # stores filename
    profile_pic_timestamp = db.Column(db.Integer, nullable=True)  # prevents caching


class DocSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120),db.ForeignKey('user.email'),nullable=False)
    location = db.Column(db.String(255),nullable=False)
    college = db.Column(db.String(255),nullable=False)
    process = db.Column(db.String(120),nullable=False)
    answers = db.Column(db.Text)  # JSON
    files = db.Column(db.Text)    # JSON list of filenames
    submitted_on = db.Column(db.DateTime, default=datetime.utcnow)

class UserDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120),db.ForeignKey('user.email'),nullable=False)
    submission_id = db.Column(db.Integer, db.ForeignKey('doc_submission.id'), nullable=True)
    doc_name = db.Column(db.String(255),nullable=False)
    filename = db.Column(db.String(255),nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_email = db.Column(db.String(120), nullable=False)
    donor_name = db.Column(db.String(120), nullable=False)
    donor_location = db.Column(db.String(255))
    item_name = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100))
    quantity = db.Column(db.Integer, nullable=False, default=1)
    condition = db.Column(db.String(50))
    image = db.Column(db.String(255))
    collection_location = db.Column(db.String(255))
    collection_time = db.Column(db.String(255))
    status = db.Column(db.String(50), default="available")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    requests = db.relationship('DonationRequest', backref='donation', lazy=True)

class DonationRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donation_id = db.Column(db.Integer, db.ForeignKey('donation.id'), nullable=False)
    requester_email = db.Column(db.String(120), nullable=False)
    requester_name = db.Column(db.String(120), nullable=False)
    requester_area = db.Column(db.String(255))
    message = db.Column(db.Text)
    status = db.Column(db.String(50), default="pending")  # pending / accepted / collected / declined
    scheduled_time = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# -------------------------
# NGO & Service Models
# -------------------------
class NGO(db.Model):
    __tablename__ = 'ngo'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(50))
    website = db.Column(db.String(300))
    contact = db.Column(db.String(200))
    areas = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class NGORequest(db.Model):
    __tablename__ = 'ngo_request'
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(120))
    email = db.Column(db.String(120))
    phone = db.Column(db.String(30))
    marks = db.Column(db.String(50))
    support_for = db.Column(db.String(500))
    ngo_id = db.Column(db.Integer, db.ForeignKey('ngo.id'))
    status = db.Column(db.String(50), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ngo = db.relationship('NGO', backref=db.backref('requests', lazy=True))

class Service(db.Model):
    __tablename__ = 'service'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    organization = db.Column(db.String(200))
    place = db.Column(db.String(200))
    start_time = db.Column(db.String(100))
    end_time = db.Column(db.String(100))
    status = db.Column(db.String(50), default='Starting Soon')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(120), nullable=False)

class ServiceRequest(db.Model):
    __tablename__ = 'service_request'
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    requester_name = db.Column(db.String(120))
    requester_email = db.Column(db.String(120))
    message = db.Column(db.Text)
    status = db.Column(db.String(50), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(120), nullable=False)
    service = db.relationship('Service', backref=db.backref('join_requests', lazy=True))


with app.app_context():
    db.create_all()

# -------------------------
# Helper Functions
# -------------------------
def send_otp_email(to_email, subject, name, otp):
    body = f"Hello {name},\n\nYour OTP is: {otp}\n\n— SRAP"
    msg = Message(subject=subject, recipients=[to_email], body=body)
    mail.send(msg)

def send_user_message(to_email, subject, body):
    msg = Message(subject=subject, recipients=[to_email], body=body)
    mail.send(msg)

def get_place_name_from_coords(lat, lon):
    try:
        url = "https://nominatim.openstreetmap.org/reverse"
        params = {"lat": lat, "lon": lon, "format": "jsonv2", "addressdetails": 1}
        resp = requests.get(url, params=params, headers={"User-Agent": "SRAP-App"}, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            addr = data.get("address", {})
            # Build a detailed address using available parts (prioritize neighbourhood/suburb/road)
            parts = []
            for key in ("neighbourhood", "suburb", "quarter", "residential", "road", "house_number"):
                if addr.get(key):
                    parts.append(addr.get(key))
            # district/county/town/city/state
            for key in ("city_district", "county", "town", "city", "state_district", "state"):
                if addr.get(key) and addr.get(key) not in parts:
                    parts.append(addr.get(key))
            display_name = ", ".join(parts) if parts else data.get("display_name")
            return display_name or "Unknown Location"
    except Exception as e:
        app.logger.debug("Reverse geocode error: %s", e)
    return "Unknown Location"

# Improved Overpass fetch: nodes/ways/relations, radius meters, dedupe names and return sorted by distance
def fetch_nearby_colleges(lat, lon, radius=5000, max_results=40, timeout_sec=20):
    try:
        # Overpass QL: look for amenity=college or amenity=university OR class=university etc.
        q = f"""
        [out:json][timeout:{timeout_sec}];
        (
          node["amenity"="college"](around:{radius},{lat},{lon});
          node["amenity"="university"](around:{radius},{lat},{lon});
          way["amenity"="college"](around:{radius},{lat},{lon});
          way["amenity"="university"](around:{radius},{lat},{lon});
          relation["amenity"="college"](around:{radius},{lat},{lon});
          relation["amenity"="university"](around:{radius},{lat},{lon});
        );
        out center {max_results};
        """
        resp = requests.post("https://overpass-api.de/api/interpreter", data=q.encode("utf-8"), timeout=timeout_sec+5)
        resp.raise_for_status()
        data = resp.json()
        results = []
        seen = set()
        for el in data.get("elements", []):
            tags = el.get("tags", {})
            name = tags.get("name")
            if not name:
                continue
            # get coordinates (node has lat/lon; way/relation has center)
            el_lat = el.get("lat") or (el.get("center") or {}).get("lat")
            el_lon = el.get("lon") or (el.get("center") or {}).get("lon")
            if el_lat is None or el_lon is None:
                continue
            key = (name.strip(), round(float(el_lat), 6), round(float(el_lon), 6))
            if key in seen:
                continue
            seen.add(key)
            # Haversine-like small-distance squared is fine for sorting in same area
            distance = math.hypot(lat - float(el_lat), lon - float(el_lon))
            results.append({"name": name.strip(), "lat": float(el_lat), "lon": float(el_lon), "distance": distance})
        # sort by distance ascending
        results.sort(key=lambda x: x["distance"])
        return results[:max_results]
    except Exception as e:
        app.logger.debug("Overpass fetch error: %s", e)
        return []

# -------------------------
# Serve uploaded files
# -------------------------
from urllib.parse import unquote
from flask import abort

@app.route('/uploads/<path:user_email>/<path:filename>', endpoint='uploaded_file')
def uploaded_file(user_email, filename):
    user_email = unquote(user_email)  # Decode %40 -> @
    user_folder = os.path.join(UPLOAD_FOLDER, user_email)
    file_path = os.path.join(user_folder, filename)

    if not os.path.exists(file_path):
        # Return a proper 404 error page instead of a string
        abort(404, description=f"File not found: {file_path}")

    return send_from_directory(user_folder, filename, as_attachment=False)

#-----------------------------------------------------------------------
# Authentication & other routes (kept as in your original file)
# ----------------------------------------------------------------------
@app.route("/")
def root():
    if session.get("username"):
        return redirect(url_for("home"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pwd = request.form.get("password", "")
        college = request.form.get("college", "").strip()
        user = User.query.filter_by(email=email, college=college).first()
        if not user or not check_password_hash(user.password, pwd):
            flash("Invalid credentials or account does not exist. Please signup.", "error")
            return redirect(url_for("login"))
        otp = str(random.randint(100000, 999999))
        session["pending_login_email"] = email
        session["pending_login_otp"] = otp
        try:
            send_otp_email(email, "SRAP Login OTP", user.name, otp)
            flash("OTP sent to your registered email.", "info")
        except Exception:
            flash("Failed to send OTP email. Check mail configuration.", "error")
            return redirect(url_for("login"))
        return render_template("login.html", step="otp", email=email)
    return render_template("login.html", step="form")

@app.route("/verify_login", methods=["POST"])
def verify_login():
    entered = request.form.get("otp", "").strip()
    otp = session.get("pending_login_otp")
    email = session.get("pending_login_email")
    if not otp or not email:
        flash("Session expired. Please login again.", "error")
        return redirect(url_for("login"))
    if entered != otp:
        flash("Invalid OTP. Please try again.", "error")
        return render_template("login.html", step="otp", email=email)
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Account not found.", "error")
        return redirect(url_for("login"))
    session.pop("pending_login_otp", None)
    session.pop("pending_login_email", None)
    session["username"] = user.name
    session["email"] = user.email
    flash("Login successful. Welcome!", "success")
    return redirect(url_for("home"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in [
            "name", "college", "email", "phone", "branch", "sem", "roll", "password", "confirmPassword"
        ]}
        form["email"] = form["email"].lower()
        if User.query.filter_by(email=form["email"]).first():
            flash("Mail ID already exists! Please login.", "error")
            return redirect(url_for("login"))
        if form["password"] != form["confirmPassword"]:
            flash("Passwords do not match.", "error")
            return render_template("signup.html", step="form", data=form)
        otp = str(random.randint(100000, 999999))
        session["signup_form"] = form
        session["signup_otp"] = otp
        try:
            send_otp_email(form["email"], "SRAP Signup OTP", form["name"], otp)
            flash("OTP sent to your email. Please verify to create your account.", "info")
        except Exception:
            flash("Failed to send OTP. Check mail configuration.", "error")
        return render_template("signup.html", step="otp", data=form)
    return render_template("signup.html", step="form")

@app.route("/verify_signup", methods=["POST"])
def verify_signup():
    entered = request.form.get("otp", "").strip()
    otp = session.get("signup_otp")
    form = session.get("signup_form")
    if not otp or not form:
        flash("Session expired. Please signup again.", "error")
        return redirect(url_for("signup"))
    if entered != otp:
        flash("Invalid OTP. Please try again.", "error")
        return render_template("signup.html", step="otp", data=form)
    hashed = generate_password_hash(form["password"])
    user = User(
        name=form["name"], college=form["college"], email=form["email"],
        phone=form["phone"], branch=form["branch"], sem=form["sem"],
        roll=form["roll"], password=hashed
    )
    db.session.add(user)
    db.session.commit()
    session.pop("signup_form", None)
    session.pop("signup_otp", None)
    flash("Account created successfully! Please login.", "success")
    return redirect(url_for("login"))

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account exists with that email.", "error")
            return redirect(url_for("forgot"))
        session["reset_email"] = email
        return redirect(url_for("forgot_mobile"))
    return render_template("forgot_email.html")

@app.route("/forgot/mobile", methods=["GET", "POST"])
def forgot_mobile():
    if "reset_email" not in session:
        return redirect(url_for("forgot"))
    if request.method == "POST":
        mobile = request.form.get("mobile", "").strip()
        user = User.query.filter_by(email=session["reset_email"]).first()
        if not user or user.phone != mobile:
            flash("Mobile number does not match.", "error")
            return redirect(url_for("forgot_mobile"))
        return redirect(url_for("forgot_college"))
    return render_template("forgot_mobile.html")

@app.route("/forgot/college", methods=["GET", "POST"])
def forgot_college():
    if "reset_email" not in session:
        return redirect(url_for("forgot"))
    if request.method == "POST":
        college = request.form.get("college", "").strip()
        user = User.query.filter_by(email=session["reset_email"]).first()
        if not user or user.college.lower() != college.lower():
            flash("College name does not match.", "error")
            return redirect(url_for("forgot_college"))
        return redirect(url_for("forgot_roll"))
    return render_template("forgot_college.html")

@app.route("/forgot/roll", methods=["GET", "POST"])
def forgot_roll():
    if "reset_email" not in session:
        return redirect(url_for("forgot"))
    if request.method == "POST":
        roll = request.form.get("roll", "").strip()
        user = User.query.filter_by(email=session["reset_email"]).first()
        if not user or user.roll != roll:
            flash("Roll number does not match.", "error")
            return redirect(url_for("forgot_roll"))
        otp = f"{random.randint(100000, 999999):06}"
        session["reset_otp"] = otp
        try:
            send_otp_email(user.email, "SRAP Password Reset OTP", user.name, otp)
            flash("OTP sent to your registered email.", "info")
        except Exception:
            flash("Error sending OTP. Please check email configuration.", "error")
            return redirect(url_for("forgot_roll"))
        return redirect(url_for("forgot_otp"))
    return render_template("forgot_roll.html")

@app.route("/forgot/otp", methods=["GET", "POST"])
def forgot_otp():
    if "reset_email" not in session or "reset_otp" not in session:
        flash("Session expired. Please restart password reset.", "error")
        return redirect(url_for("forgot"))
    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()
        actual_otp = session.get("reset_otp")
        if entered_otp != str(actual_otp):
            flash("Invalid OTP. Please try again.", "error")
            return render_template("forgot_otp.html")
        session.pop("reset_otp", None)
        flash("OTP verified! Please reset your password.", "success")
        return redirect(url_for("reset_password"))
    return render_template("forgot_otp.html")

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if "reset_email" not in session:
        return redirect(url_for("forgot"))
    if request.method == "POST":
        pwd1 = request.form.get("password")
        pwd2 = request.form.get("confirmPassword")
        if pwd1 != pwd2:
            flash("Passwords do not match.", "error")
            return redirect(url_for("reset_password"))
        user = User.query.filter_by(email=session["reset_email"]).first()
        if not user:
            flash("Account not found.", "error")
            return redirect(url_for("forgot"))
        user.password = generate_password_hash(pwd1)
        db.session.commit()
        session.pop("reset_email", None)
        session.pop("reset_otp", None)
        flash("Password reset successful. Please login with your new password.", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html")

# -------------------------
# HOME ROUTE
# -------------------------
@app.route("/home")
def home():
    if "email" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))
    
    # Safely get name or fallback to email
    username = session.get("name") or session.get("email", "User")
    return render_template("home.html", username=username)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# -------------------------
# Doc Helper Route
# -------------------------
@app.route("/doc_helper", methods=["GET", "POST"])
def doc_helper():
    if "email" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    user_email = session["email"]
    # ensure doc_helper session bucket exists
    if "doc_helper" not in session:
        session["doc_helper"] = {}
    data = session.get("doc_helper", {})

    # GET: render page with current session values + previously uploaded files
    if request.method == "GET":
        prev_docs = UserDocument.query.filter_by(user_email=user_email).all()
        prev_files = [d.filename for d in prev_docs]
        user = User.query.filter_by(email=user_email).first()
        # Build user_data defaults (prefer session's stored values)
        stored_ud = data.get("user_details", {}) or {}
        user_data = {
            "name": stored_ud.get("name") or (user.name if user else ""),
            "roll": stored_ud.get("roll") or (user.roll if user else ""),
            "branch": stored_ud.get("branch") or (user.branch if user else ""),
            "year": stored_ud.get("year") or "",
            "amount": stored_ud.get("amount") or ""
        }
        return render_template(
            "doc_helper.html",
            location=data.get("location", ""),
            college=data.get("college", ""),
            process=data.get("process", ""),
            user_data=user_data,
            uploaded_doc=prev_files
        )

    # POST: step handling
    step = request.form.get("step")
    if not step:
        return jsonify({"status": "error", "message": "Missing step"}), 400

    # STEP 1: Location + college suggestions
    if step == "1":
        # location may be a manually typed string or lat/lon fields provided by front-end
        location_input = request.form.get("location", "").strip()
        college_input = request.form.get("college", "").strip()
        lat = request.form.get("latitude")
        lon = request.form.get("longitude")

        # If lat/lon provided, reverse geocode to detailed area string, and fetch nearby colleges
        suggestions = []
        detailed_location = location_input
        lat_f = lon_f = None
        if lat and lon:
            try:
                lat_f = float(lat)
                lon_f = float(lon)
                detailed_location = get_place_name_from_coords(lat_f, lon_f) or location_input or f"{lat},{lon}"
                # fetch nearby colleges (name, lat, lon, distance)
                colleges = fetch_nearby_colleges(lat_f, lon_f, radius=8000, max_results=30)
                # prepare simplified suggestions (name + short distance in meters)
                suggestions = [
                    {"name": c["name"], "lat": c["lat"], "lon": c["lon"]}
                    for c in colleges
                ]
            except Exception as e:
                app.logger.debug("Error parsing coords in step1: %s", e)
                detailed_location = location_input or detailed_location
        else:
            # If only a typed location exists, we can try to use nominatim search to resolve a lat/lon (optional)
            if location_input:
                try:
                    r = requests.get("https://nominatim.openstreetmap.org/search",
                                     params={"q": location_input, "format": "jsonv2", "limit": 1},
                                     headers={"User-Agent": "SRAP-App"}, timeout=8)
                    if r.status_code == 200 and r.json():
                        first = r.json()[0]
                        lat_f = float(first.get("lat"))
                        lon_f = float(first.get("lon"))
                        # use reverse to build nicer address
                        detailed_location = get_place_name_from_coords(lat_f, lon_f)
                        colleges = fetch_nearby_colleges(lat_f, lon_f, radius=8000, max_results=20)
                        suggestions = [{"name": c["name"], "lat": c["lat"], "lon": c["lon"]} for c in colleges]
                except Exception as e:
                    app.logger.debug("Nominatim search error (step1): %s", e)

        # store chosen details in session (do not overwrite process or user details)
        data.update({"location": detailed_location, "college": college_input})
        session["doc_helper"] = data

        # ✅ Rename key to match frontend expectation
        return jsonify({
            "status": "success",
            "next_step": 2,
            "colleges": suggestions
})


    # STEP 2: Process selection
    if step == "2":
        process = (request.form.get("process") or "").strip()
        if not process:
            return jsonify({"status": "error", "message": "Process required"}), 400
        data["process"] = process
        session["doc_helper"] = data
        return jsonify({"status": "success", "next_step": 3})

    # STEP 3: details + file handling; show required docs if present in excel
    if step == "3":
        # ---------------------
        # Capture user details
        # ---------------------
        user_details = {
            "name": (request.form.get("name") or "").strip(),
            "roll": (request.form.get("roll") or "").strip(),
            "branch": (request.form.get("branch") or "").strip(),
            "year": (request.form.get("year") or "").strip(),
            "semester": (request.form.get("semester") or "").strip(),
            "amount": (request.form.get("amount") or "").strip()
        }
        data["user_details"] = user_details

        # ---------------------
        # Initialize uploaded files
        # ---------------------
        uploaded_files = data.get("uploaded_doc", [])
        if not isinstance(uploaded_files, list):
            uploaded_files = []

        # ---------------------
        # Fetch or create submission
        # ---------------------
        submission = DocSubmission.query.filter_by(
            user_email=user_email,
            location=data.get("location", ""),
            college=data.get("college", ""),
            process=data.get("process", "")
        ).first()

        answers_json = json.dumps(user_details)

        if submission:
            submission.answers = answers_json
            submission.files = json.dumps(uploaded_files)
            submission.submitted_on = datetime.utcnow()
        else:
            submission = DocSubmission(
                user_email=user_email,
                location=data.get("location", ""),
                college=data.get("college", ""),
                process=data.get("process", ""),
                answers=answers_json,
                files=json.dumps(uploaded_files),
                submitted_on=datetime.utcnow()
            )
            db.session.add(submission)

        db.session.commit()

        # ---------------------
        # Remove files if requested
        # ---------------------
        removed = request.form.getlist("remove_files[]")
        if removed:
            user_folder = os.path.join(UPLOAD_FOLDER, user_email)
            uploaded_files = [f for f in uploaded_files if f["stored"] not in removed]
            for f in removed:
                try:
                    fp = os.path.join(user_folder, f)
                    if os.path.exists(fp):
                        os.remove(fp)
                    UserDocument.query.filter_by(user_email=user_email, filename=f).delete()
                except Exception as e:
                    app.logger.debug("Error deleting file %s: %s", f, e)
            db.session.commit()

        # ---------------------
        # Handle newly uploaded files
        # ---------------------
        files = request.files.getlist("documents")
        if files:
            user_folder = os.path.join(UPLOAD_FOLDER, user_email)
            os.makedirs(user_folder, exist_ok=True)

            for file in files:
                if not file or file.filename == "":
                    continue
                if not allowed_file(file.filename):
                    return jsonify({"status": "error", "message": "File type not allowed"}), 400

                safe_name = secure_filename(file.filename)
                filename = f"{uuid.uuid4().hex}_{safe_name}"
                dest = os.path.join(user_folder, filename)

                try:
                    file.save(dest)
                    file_info = {
                        "display": safe_name,    # original filename
                        "stored": filename,      # saved filename with UUID
                        "uploaded_at": datetime.utcnow().strftime("%d %b %Y, %I:%M %p")
                    }
                    uploaded_files.append(file_info)

                    # Save in DB
                    ud = UserDocument(
                        user_email=user_email,
                        submission_id=submission.id,
                        doc_name=safe_name,
                        filename=filename
                    )
                    db.session.add(ud)
                except Exception as e:
                    app.logger.debug("Error saving uploaded file: %s", e)

            db.session.commit()

        # ---------------------
        # Update session
        # ---------------------
        data["uploaded_doc"] = uploaded_files
        session["doc_helper"] = data

        # ---------------------
        # Optional: required docs from Excel
        # ---------------------
        required_docs = []
        college_name = data.get("college", "") or ""
        if not college_data.empty and college_name:
            matches = college_data[college_data["College"].str.lower().str.contains(college_name.lower(), na=False)]
            if matches.empty:
                matches = college_data[college_data["College"].str.lower().str.contains(college_name.split()[0].lower(), na=False)]
            for _, r in matches.iterrows():
                docval = r.get("Document_Name") or r.get("Required Documents") or ""
                if isinstance(docval, str):
                    for d in [x.strip() for x in docval.split(",") if x.strip()]:
                        if d and d not in required_docs:
                            required_docs.append(d)

        # ---------------------
        # Return summary JSON
        # ---------------------
        return jsonify({
            "status": "success",
            "next_step": 4,
            "location": data.get("location"),
            "college": data.get("college"),
            "process": data.get("process"),
            "name": user_details.get("name"),
            "branch": user_details.get("branch"),
            "year": user_details.get("year"),
            "roll": user_details.get("roll"),
            "files": uploaded_files,
            "submitted_on": submission.submitted_on.strftime("%d %b %Y, %I:%M %p"),
            "user_email": user_email    # ✅ ADD THIS
})


@app.route("/doc_summary")
def doc_summary():
    if "email" not in session:
        flash("Please login first.", "error")
        return redirect(url_for("login"))
    
    user_email = session["email"]

    # Fetch user's submissions (latest first)
    submissions = DocSubmission.query.filter_by(user_email=user_email).order_by(DocSubmission.id.desc()).all()
    
    docs = []
    for s in submissions:
        # Load answers JSON
        answers_dict = json.loads(s.answers) if s.answers else {}

        # Convert submitted_on to datetime if it's a string
        submitted_on = s.submitted_on
        if isinstance(submitted_on, str):
            try:
                submitted_on = datetime.strptime(submitted_on, "%Y-%m-%d %H:%M:%S")
            except Exception:
                submitted_on = None

        # Fetch only files related to this submission
        files_info = UserDocument.query.filter_by(user_email=user_email, submission_id=s.id).all()
        files = [
            {
                "display": f.doc_name,
                "stored": f.filename,
                "uploaded_at": f.uploaded_at.strftime("%d %b %Y, %I:%M %p")
            } for f in files_info
        ]


        # Build document dictionary for template
        docs.append({
            "id": s.id,
            "location": s.location,
            "college": s.college,
            "process": s.process,
            "answers": answers_dict,
            "files": files,
            "submitted_on": submitted_on.strftime("%d %b %Y, %I:%M %p") if submitted_on else "N/A",
            "name": answers_dict.get("name",""),
            "branch": answers_dict.get("branch",""),
            "year": answers_dict.get("year",""),
            "roll": answers_dict.get("roll",""),
            "email": s.user_email    # ✅ ADD THIS
})
    return render_template("doc_summary.html", docs=docs)



@app.route("/request_admin", methods=["POST"])
def request_admin():
    if "email" not in session:
        return jsonify({"status": "error", "message": "Login required"}), 401

    data = request.get_json() or {}
    doc_req_name = data.get("doc_name", "")
    process_name = data.get("process", "")
    college_name = session.get("doc_helper", {}).get("college", "")
    user_email = session["email"]
    user_name = session.get("username", user_email)

    try:
        # ✅ Build clear and friendly body
        body = (
            f"Hello {user_name},\n\n"
            f"Your request of the unavaliable document for the '{process_name}' process "
            f"has been successfully sent to the admin of '{college_name}'.\n\n"
            f"You will be notified once the admin responds and u can use this mail at administration desk.\n\n"
            f"— Team SRAP"
        )

        # ✅ Send email to the logged-in user only
        send_user_message(
            to_email=user_email,
            subject="SRAP — Document Request Confirmation",
            body=body
        )

        # ✅ Return success response for frontend popup
        return jsonify({
            "status": "success",
            "message": f"Your request for '{doc_req_name}' in the '{process_name}' process has been sent to the admin successfully."
        })

    except Exception as e:
        app.logger.debug("Request admin email error: %s", e)
        return jsonify({
            "status": "error",
            "message": "Failed to send confirmation email. Please try again later."
        }), 500
    
# -------------------------
# Donation Routes
# -------------------------

# 1️⃣ Donation entry
@app.route("/donation")
def donation_entry():
    if "username" not in session:
        flash("Please login to access donation module", "error")
        return redirect(url_for("login"))
    return render_template("donation.html")

# 2️⃣ Donor: post donation
@app.route("/donate", methods=["GET","POST"])
def donate():
    if "username" not in session:
        flash("Please login to donate.", "error")
        return redirect(url_for("login"))

    if request.method=="POST":
        donor_name = session.get("username")
        donor_email = session.get("email")
        donor_location = request.form.get("location","").strip()
        item_name = request.form.get("item_name","").strip()
        category = request.form.get("category","").strip()
        try: quantity = max(1,int(request.form.get("quantity",1)))
        except: quantity = 1
        condition = request.form.get("condition","").strip()
        collection_location = request.form.get("collection_location","").strip()
        collection_time = request.form.get("collection_time","").strip()

        # Image
        image_file = request.files.get("image")
        image_filename = None
        if image_file and image_file.filename:
            ext = image_file.filename.rsplit(".",1)[-1].lower()
            if ext in ALLOWED_EXTENSIONS:
                filename = f"{uuid.uuid4().hex}_{secure_filename(image_file.filename)}"
                image_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                image_filename = filename

        donation = Donation(
            donor_email=donor_email,
            donor_name=donor_name,
            donor_location=donor_location,
            item_name=item_name,
            category=category,
            quantity=quantity,
            condition=condition,
            image=image_filename,
            collection_location=collection_location,
            collection_time=collection_time
        )
        db.session.add(donation)
        db.session.commit()
        flash("Donation posted successfully!", "success")
        return redirect(url_for("donations_home"))

    return render_template("donate.html")

# 3️⃣ List all donations (receiver) and include user's requests
@app.route("/donations")
def donations_home():
    if "username" not in session:
        flash("Please login to view donations", "error")
        return redirect(url_for("login"))

    item_query = request.args.get("item","").strip()
    area_query = request.args.get("area","").strip()

    # Available donations (not collected)
    query = Donation.query.filter(Donation.status!="collected")
    if item_query:
        query = query.filter(Donation.item_name.ilike(f"%{item_query}%"))
    if area_query:
        query = query.filter(Donation.donor_location.ilike(f"%{area_query}%"))
    donations = query.order_by(Donation.created_at.desc()).all()

    # Requests made by this logged-in user
    user_email = session.get("email")
    requests = DonationRequest.query.filter_by(requester_email=user_email)\
                .order_by(DonationRequest.created_at.desc()).all()

    return render_template("donations_home.html", donations=donations, requests=requests)



# 4️⃣ Request item
@app.route("/request_item/<int:donation_id>", methods=["GET","POST"])
def request_item(donation_id):
    if "username" not in session:
        if request.method=="POST":
            return jsonify({"status":"error","message":"Login required"}),403
        return redirect(url_for("login"))

    donation = Donation.query.get_or_404(donation_id)

    if request.method=="POST":
        requester_name = request.form.get("requester_name","").strip()
        requester_email = request.form.get("requester_email","").strip()
        requester_area = request.form.get("requester_area","").strip()
        message = request.form.get("message","").strip()

        if not requester_name or not requester_email:
            return jsonify({"status":"error","message":"Name and email required"}),400

        existing = DonationRequest.query.filter_by(
            donation_id=donation.id,
            requester_email=requester_email
        ).first()
        if existing:
            return jsonify({"status":"error","message":"You already requested this item"}),400

        rand_min = random.randint(60,720)
        scheduled_dt = datetime.utcnow() + timedelta(minutes=rand_min)
        scheduled_text = scheduled_dt.strftime("%Y-%m-%d %H:%M UTC")

        donation_request = DonationRequest(
            donation_id=donation.id,
            requester_email=requester_email,
            requester_name=requester_name,
            requester_area=requester_area,
            message=message,
            scheduled_time=scheduled_text
        )
        db.session.add(donation_request)
        donation.status = "requested"
        db.session.commit()

        # Emails (ignore errors)
        try:
            donor_body = f"""
Hi, this is Team SRAP!

{requester_name} has requested your item: {donation.item_name}
Requester Email: {requester_email}
Pickup Location: {donation.collection_location}
Pickup Time: {scheduled_text}
Message: {message or 'No message'}
"""
            msg = Message(f"Update: Your item '{donation.item_name}' has a new request",
                          recipients=[donation.donor_email],
                          body=donor_body)
            mail.send(msg)
        except: pass

        try:
            requester_body = f"""
Hi, this is Team SRAP!

Your request for '{donation.item_name}' of {donation.donor_name} has been sent.
Donor Email: {donation.donor_email}
Pickup Location: {donation.collection_location}
Pickup Time: {scheduled_text}
Message: {message or 'No message'}
"""
            msg2 = Message(f"Request Sent: '{donation.item_name}'",
                           recipients=[requester_email],
                           body=requester_body)
            mail.send(msg2)
        except: pass

        return jsonify({"status":"success","message":"Request sent","scheduled_time":scheduled_text})

    return render_template("request_item.html", donation=donation)


# 5️⃣ Mark request collected
@app.route("/request_collected/<int:request_id>", methods=["POST"])
def request_collected(request_id):
    if "username" not in session:
        return jsonify({"status":"error","message":"Login required"}),403

    req = DonationRequest.query.get_or_404(request_id)
    donation = Donation.query.get(req.donation_id)

    if req.requester_email != session.get("email"):
        return jsonify({"status":"error","message":"Unauthorized"}),403

    req.status = "collected"
    donation.status = "collected"
    db.session.commit()
    return jsonify({"status":"success","message":"Marked as collected"})


from flask import render_template, session, flash, redirect, url_for
from sqlalchemy.orm import joinedload

@app.route("/donor_home")
def donor_home():
    if "username" not in session:
        flash("Please login", "error")
        return redirect(url_for("login"))

    donor_email = session.get("email")

    # Donor's donations
    donations = Donation.query.filter_by(donor_email=donor_email)\
        .order_by(Donation.created_at.desc()).all()

    # Incoming requests for these donations (eager load donation to avoid None)
    requests = DonationRequest.query.options(joinedload(DonationRequest.donation))\
        .join(Donation)\
        .filter(Donation.donor_email == donor_email)\
        .order_by(DonationRequest.created_at.desc()).all()

    return render_template("donor_home.html", donations=donations, requests=requests)



# 7️⃣ Manage incoming requests
@app.route("/manage_requests")
def manage_requests():
    if "username" not in session:
        flash("Login required", "error")
        return redirect(url_for("login"))

    donor_email = session.get("email")
    requests = DonationRequest.query.join(Donation).filter(Donation.donor_email==donor_email)\
        .order_by(DonationRequest.created_at.desc()).all()
    return render_template("manage_requests.html", requests=requests)


# 8️⃣ Update request status
@app.route("/update_request_status/<int:request_id>", methods=["POST"])
def update_request_status(request_id):
    if "username" not in session:
        return jsonify({"status":"error","message":"Login required"}),403

    req = DonationRequest.query.get_or_404(request_id)
    donation = Donation.query.get(req.donation_id)
    if donation.donor_email != session.get("email"):
        return jsonify({"status":"error","message":"Unauthorized"}),403

    action = request.form.get("action")
    if action=="approve":
        req.status="accepted"
        donation.status="requested"
    elif action=="decline":
        req.status="declined"
        donation.status="available"
    else:
        return jsonify({"status":"error","message":"Invalid action"}),400

    db.session.commit()
    return jsonify({"status":"success","message":f"Request {action}d"})


# 9️⃣ Receiver: my requests
@app.route("/my_requests")
def my_requests():
    if "username" not in session:
        flash("Login required","error")
        return redirect(url_for("login"))

    requests = DonationRequest.query.filter_by(requester_email=session.get("email"))\
        .order_by(DonationRequest.created_at.desc()).all()
    return render_template("my_requests.html", requests=requests)



#-----------------------------------
# LOCAL ASSISTANT
#-----------------------------------

@app.route("/local_assistant")
def local_assistant():
    if "username" not in session:
        flash("Please login", "error")
        return redirect(url_for("login"))
    return render_template("local_assistant.html", username=session.get("username"))


#-----------------------
#CHATERHALL
#--------------------

@app.route("/chatterhall")
def chatterhall():
    # Redirect SRAP users to your Node.js chat app
    return redirect("http://localhost:5000")


# -------------------------
# Decorators
# -------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash('Login required', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# -------------------------
# NGO Routes
# -------------------------
@app.route('/ngo_dashboard')
def ngo_dashboard():
    ngos = NGO.query.order_by(NGO.created_at.desc()).all()
    return render_template('ngo_dashboard.html', ngos=ngos)

@app.route('/add_ngo', methods=['GET', 'POST'])
@login_required
def add_ngo():
    if request.method == 'POST':
        name = request.form.get('name')
        type_ = request.form.get('type')
        website = request.form.get('website')
        contact = request.form.get('contact')
        areas = request.form.get('areas')
        if not name:
            flash('Organization name is required', 'error')
            return redirect(url_for('add_ngo'))
        ngo = NGO(name=name, type=type_, website=website, contact=contact, areas=areas)
        db.session.add(ngo)
        db.session.commit()
        flash('NGO added successfully', 'success')
        return redirect(url_for('ngo_dashboard'))
    return render_template('ngo_add.html')

@app.route('/ngo_request_help', methods=['GET', 'POST'])
@login_required
def ngo_request_help():
    ngo_id = request.args.get('ngo_id') or request.form.get('ngo_id')
    if request.method == 'POST':
        user_name = request.form.get('user_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        marks = request.form.get('marks')
        support_for = request.form.get('support_for')
        ngo_id = request.form.get('ngo_id') or None

        if not (user_name and email and support_for):
            flash('Please fill name, email and support details', 'error')
            return redirect(url_for('ngo_request_help', ngo_id=ngo_id))

        req = NGORequest(
            user_name=user_name,
            email=email,
            phone=phone,
            marks=marks,
            support_for=support_for,
            ngo_id=ngo_id
        )
        db.session.add(req)
        db.session.commit()
        flash('Request submitted to NGO', 'success')
        return redirect(url_for('ngo_manage_request'))

    ngos = NGO.query.order_by(NGO.name).all()
    return render_template('ngo_request_help.html', ngo_id=ngo_id, ngos=ngos)

@app.route('/ngo_manage_request')
@login_required
def ngo_manage_request():
    ngo_id = request.args.get('ngo_id')
    if ngo_id:
        requests_ = NGORequest.query.filter_by(ngo_id=ngo_id).order_by(NGORequest.created_at.desc()).all()
    else:
        requests_ = NGORequest.query.filter_by(email=session.get('email')).order_by(NGORequest.created_at.desc()).all()
    return render_template('ngo_manage_request.html', requests=requests_)

@app.route('/ngo_mark_helped/<int:req_id>', methods=['POST'])
@login_required
def ngo_mark_helped(req_id):
    r = NGORequest.query.get_or_404(req_id)
    if r.email != session.get('email'):
        flash('Unauthorized', 'error')
        return redirect(url_for('ngo_manage_request'))
    r.status = 'Helped'
    db.session.commit()
    flash('Marked request as helped', 'success')
    return redirect(url_for('ngo_manage_request'))

@app.route('/ngo_delete_request/<int:req_id>', methods=['POST'])
@login_required
def ngo_delete_request(req_id):
    r = NGORequest.query.get_or_404(req_id)
    if r.email != session.get('email'):
        flash('Unauthorized', 'error')
        return redirect(url_for('ngo_manage_request'))
    db.session.delete(r)
    db.session.commit()
    flash('Request deleted', 'success')
    return redirect(url_for('ngo_manage_request'))

# -------------------------
# Service Routes
# -------------------------
@app.route('/service_dashboard')
def service_dashboard():
    services = Service.query.order_by(Service.created_at.desc()).all()
    return render_template('service_dashboard.html', services=services)

@app.route('/create_service', methods=['GET', 'POST'])
@login_required
def create_service():
    if request.method == 'POST':
        name = request.form.get('name')
        organization = request.form.get('organization')
        place = request.form.get('place')
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')

        if not name:
            flash('Event name is required', 'error')
            return redirect(url_for('create_service'))

        s = Service(
            name=name,
            organization=organization,
            place=place,
            start_time=start_time,
            end_time=end_time,
            created_by=session.get('email')
        )
        db.session.add(s)
        db.session.commit()
        flash('Service created', 'success')
        return redirect(url_for('service_dashboard'))

    return render_template('service_create.html')

@app.route('/my_services')
@login_required
def my_services():
    services = Service.query.filter_by(created_by=session.get('email')).order_by(Service.created_at.desc()).all()
    return render_template('service_my.html', services=services)

@app.route('/service_change_status/<int:sid>', methods=['POST'])
@login_required
def service_change_status(sid):
    s = Service.query.get_or_404(sid)
    if s.created_by != session.get('email'):
        flash('Unauthorized: only service creator can change status', 'error')
        return redirect(url_for('my_services'))

    status = request.form.get('status')
    if status:
        s.status = status
        db.session.commit()
        flash('Service status updated', 'success')
    return redirect(url_for('my_services'))

@app.route('/service_join/<int:sid>', methods=['GET', 'POST'])
@login_required
def service_join(sid):
    service = Service.query.get_or_404(sid)
    if request.method == 'POST':
        requester_name = request.form.get('requester_name') or session.get('username')
        requester_email = request.form.get('requester_email') or session.get('email')
        message = request.form.get('message') or ''

        r = ServiceRequest(
            service_id=sid,
            requester_name=requester_name,
            requester_email=requester_email,
            message=message,
            created_by=session.get('email')
        )
        db.session.add(r)
        db.session.commit()
        flash('Requested to join the service', 'success')
        return redirect(url_for('service_dashboard'))

    return render_template('service_join.html', service=service)

# Manage service page
@app.route('/manage_service/<int:sid>')
@login_required
def manage_service(sid):
    # Get the service or 404
    service = Service.query.get_or_404(sid)

    # Only the creator of the service can manage it
    current_user_email = session.get('email')
    if service.created_by != current_user_email:
        flash('Unauthorized: only the service creator can manage requests', 'error')
        return redirect(url_for('my_services'))

    # Get all requests for this service, newest first
    requests_ = ServiceRequest.query.filter_by(service_id=sid)\
                                   .order_by(ServiceRequest.created_at.desc())\
                                   .all()

    # Render the manage page with requests and service details
    return render_template('service_manage.html', requests=requests_, service=service)



# AJAX route for updating request status
@app.route('/service_request_action_ajax', methods=['POST'])
@login_required
def service_request_action_ajax():
    data = request.get_json()
    rid = data.get('rid')
    action = data.get('action')

    if not rid or action not in ['accept', 'decline']:
        return jsonify({'status': 'error', 'message': 'Invalid request'}), 400

    # Fetch the service request
    req = ServiceRequest.query.get(rid)
    if not req:
        return jsonify({'status': 'error', 'message': 'Request not found'}), 404

    # Only the creator of the service can update request
    service = Service.query.get(req.service_id)
    current_user_email = session.get('email')
    if service.created_by != current_user_email:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

    # Update status
    req.status = 'Accepted' if action == 'accept' else 'Declined'
    db.session.commit()

    return jsonify({'status': 'success', 'new_status': req.status})

@app.route('/delete_service/<int:sid>', methods=['POST', 'GET'])
@login_required
def delete_service(sid):
    service = Service.query.get_or_404(sid)

    # Only the creator can delete it
    if service.created_by != session.get('email'):
        flash('Unauthorized: You can only delete your own services.', 'error')
        return redirect(url_for('my_services'))

    db.session.delete(service)
    db.session.commit()
    flash('Service deleted successfully!', 'success')
    return redirect(url_for('my_services'))

#---------------------
#PROFILE
#---------------------

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'email' not in session:
        flash('Please login first.', 'error')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=session['email']).first()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Update editable fields
        user.name = request.form.get('name')
        user.phone = request.form.get('phone')
        user.branch = request.form.get('branch')
        user.sem = request.form.get('semester')
        user.roll = request.form.get('roll')

        # Handle profile picture upload
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(PROFILE_PIC_FOLDER, filename)

                # Delete old profile picture if exists
                if getattr(user, 'profile_pic', None):
                    old_file_path = os.path.join(PROFILE_PIC_FOLDER, user.profile_pic)
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)

                # Save new file
                file.save(file_path)
                user.profile_pic = filename
                user.profile_pic_timestamp = int(datetime.utcnow().timestamp())  # prevent caching

        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            # Re-fetch user to ensure template sees latest changes
            user = User.query.filter_by(email=session['email']).first()
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'error')

        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    app.run(debug=True)

