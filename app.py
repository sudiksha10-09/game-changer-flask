import os
import json
import random
import string
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    session,
    jsonify,
    abort,
)
try:
    import gspread
    from google.oauth2.service_account import Credentials
    GOOGLE_SHEETS_AVAILABLE = True
except ImportError:
    GOOGLE_SHEETS_AVAILABLE = False
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from slugify import slugify
from dotenv import load_dotenv
from markupsafe import escape

load_dotenv()

# ---------- STRIPE CONFIG & LOGGING ----------
import logging
import stripe

# Basic logging to stdout for Render / local visibility
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Log Google Sheets availability after logger is initialized
if not GOOGLE_SHEETS_AVAILABLE:
    logger.warning("Google Sheets libraries not installed. Install gspread and google-auth to enable.")

# Stripe environment vars (set these in .env locally, and in Render secrets in production)
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY
else:
    logger.warning("STRIPE_SECRET_KEY not set — Stripe disabled.")

# ---------------------------------
# PATHS
# ---------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# ---------------------------------
# APP CONFIG
# ---------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key-change-this")

# ---- EMAIL CONFIGURATION (GMAIL) ----
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = "sudiksha746@gmail.com"

mail = Mail(app)

# ---- DB Configuration ----
DB_URL = os.getenv("DATABASE_URL")

# Fix for SQLAlchemy (Postgres URLs must start with postgresql://, not postgres://)
if DB_URL and DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DB_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# --- FIX FOR SSL DISCONNECTS ---
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,  # Checks if connection is alive before using it
    "pool_recycle": 300,  # Refreshes connection every 5 minutes
}

# Initialize DB
db = SQLAlchemy(app)

# ---- File Upload Configuration ----
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Login Manager Configuration
login_manager = LoginManager(app)
login_manager.login_view = "login"

SPORTS_LIST = [
    "Cricket",
    "Football",
    "Badminton",
    "Kabaddi",
    "Hockey",
    "Athletics",
    "Swimming",
    "Tennis",
    "Table Tennis",
    "Basketball",
    "Volleyball",
    "Wrestling",
    "Boxing",
    "Shooting",
    "Archery",
    "Weightlifting",
    "Gymnastics",
    "Judo",
    "Squash",
    "Chess",
]


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ---------------------------------
# VALIDATION & SECURITY HELPERS
# ---------------------------------

def validate_email(email):
    """Validate email format"""
    if not email or len(email) > 120:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_password(password):
    """Validate password strength"""
    if not password:
        return False, "Password is required"
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if len(password) > 128:
        return False, "Password must be less than 128 characters"
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, "Valid password"


def validate_name(name):
    """Validate name field"""
    if not name or len(name.strip()) < 2:
        return False, "Name must be at least 2 characters long"
    if len(name) > 120:
        return False, "Name must be less than 120 characters"
    if not re.match(r'^[a-zA-Z\s\-\'\.]+$', name):
        return False, "Name contains invalid characters"
    return True, "Valid name"


def validate_phone(phone):
    """Validate phone number"""
    if not phone:
        return True, "Phone is optional"
    phone_clean = re.sub(r'[\s\-\(\)]', '', phone)
    if not re.match(r'^\+?[1-9]\d{9,14}$', phone_clean):
        return False, "Invalid phone number format"
    return True, "Valid phone"


def sanitize_input(text, max_length=None):
    """Sanitize user input to prevent XSS"""
    if not text:
        return ""
    text = str(text).strip()
    if max_length and len(text) > max_length:
        text = text[:max_length]
    return escape(text)


def validate_date(date_str):
    """Validate date string format"""
    try:
        date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
        if date_obj < datetime.now().date():
            return False, "Date cannot be in the past"
        if date_obj > datetime.now().date() + timedelta(days=365):
            return False, "Date cannot be more than 1 year in the future"
        return True, date_obj
    except ValueError:
        return False, "Invalid date format"


def validate_time(time_str):
    """Validate time slot format"""
    if not time_str:
        return False, "Time is required"
    pattern = r'^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$'
    if not re.match(pattern, time_str):
        return False, "Invalid time format (use HH:MM)"
    return True, time_str


def validate_price(price_str):
    """Validate price input"""
    try:
        price = int(price_str)
        if price < 0:
            return False, "Price cannot be negative"
        if price > 100000:
            return False, "Price cannot exceed ₹100,000"
        return True, price
    except (ValueError, TypeError):
        return False, "Price must be a valid number"


def validate_json_input(data, required_fields=None, field_types=None):
    """Validate JSON input for API endpoints"""
    if not isinstance(data, dict):
        return False, "Invalid JSON format"
    
    if required_fields:
        for field in required_fields:
            if field not in data:
                return False, f"Missing required field: {field}"
    
    if field_types:
        for field, expected_type in field_types.items():
            if field in data and not isinstance(data[field], expected_type):
                return False, f"Invalid type for field: {field}"
    
    return True, "Valid input"


# Rate limiting storage (in production, use Redis)
_rate_limit_storage = {}


def rate_limit(max_requests=5, window_seconds=60):
    """Simple rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_id = request.remote_addr
            key = f"{f.__name__}:{client_id}"
            now = datetime.now()
            
            if key in _rate_limit_storage:
                requests, window_start = _rate_limit_storage[key]
                if (now - window_start).seconds < window_seconds:
                    if requests >= max_requests:
                        logger.warning(f"Rate limit exceeded for {client_id} on {f.__name__}")
                        return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429
                    _rate_limit_storage[key] = (requests + 1, window_start)
                else:
                    _rate_limit_storage[key] = (1, now)
            else:
                _rate_limit_storage[key] = (1, now)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# Authorization decorators
def coach_required(f):
    """Decorator to ensure user is a coach"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != "coach":
            flash("Access denied. Coach access required.", "danger")
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return decorated_function


def hirer_required(f):
    """Decorator to ensure user is a hirer"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != "hirer":
            flash("Access denied. Student/Hirer access required.", "danger")
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to ensure user is admin"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.email != app.config["MAIL_USERNAME"]:
            flash("Access denied. Admin access required.", "danger")
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return decorated_function


def validate_file_upload(file):
    """Comprehensive file upload validation"""
    if not file or file.filename == "":
        return False, "No file selected"
    
    if not allowed_file(file.filename):
        return False, "Invalid file type. Only PNG, JPG, and JPEG are allowed"
    
    # Check file size (max 5MB)
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    
    if file_size > 5 * 1024 * 1024:  # 5MB
        return False, "File size exceeds 5MB limit"
    
    if file_size == 0:
        return False, "File is empty"
    
    return True, "Valid file"


# ---------------------------------
# MODELS
# ---------------------------------
class StripeEvent(db.Model):
    """
    Stores processed Stripe event IDs to make webhook handling idempotent.
    """
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey("coach.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1 to 5
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to access the student's name
    student = db.relationship("User", backref="reviews_written", lazy=True)


class Subscriber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20), default="hirer")  # 'coach' or 'hirer'
    is_organization = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(120), nullable=False)
    city = db.Column(db.String(120))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    # Stripe fields
    stripe_customer_id = db.Column(db.String(255), nullable=True)   # stores the Stripe Customer ID
    stripe_session_id = db.Column(db.String(255), nullable=True)    # last successful checkout session id

    # Relationships
    coach_profile = db.relationship("Coach", backref="user", uselist=False)
    bookings_made = db.relationship("Booking", backref="student", lazy=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

class Coach(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    slug = db.Column(db.String(150), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    sport = db.Column(db.String(500), nullable=False)
    sports_prices = db.Column(db.Text, default="{}")
    pincode = db.Column(db.String(10))
    state = db.Column(db.String(100))
    city = db.Column(db.String(120), nullable=False)
    price_per_session = db.Column(db.Integer, nullable=False)
    experience_years = db.Column(db.Integer, default=0)
    rating = db.Column(db.Float, default=0.0)
    tagline = db.Column(db.String(255))
    specialties = db.Column(db.Text)
    age = db.Column(db.Integer)
    phone = db.Column(db.String(15))
    profile_image = db.Column(db.String(300), default="default_coach.jpg")
    achievements = db.Column(db.Text)
    is_verified = db.Column(db.Boolean, default=False)
    # 0 means "I don't travel / At my venue only"
    travel_radius = db.Column(db.Integer, default=0)

    reviews = db.relationship(
        "Review", backref="coach", lazy=True, cascade="all, delete-orphan"
    )

    # Relationships
    bookings_received = db.relationship("Booking", backref="coach", lazy=True)

    def get_whatsapp_url(self):
        if not self.phone:
            return "#"

        clean_number = "".join(filter(str.isdigit, self.phone))
        if len(clean_number) == 10:
            clean_number = "91" + clean_number

        message = (
            f"Hi {self.name}, I saw your profile on GameChanger and I am interested in training."
        )
        message = message.replace(" ", "%20")

        return f"https://wa.me/{clean_number}?text={message}"

    def get_sports_list(self):
        return self.sport.split(",") if self.sport else []

    def get_price_dict(self):
        try:
            return json.loads(self.sports_prices) if self.sports_prices else {}
        except Exception:
            return {}
    
    def calculate_rating(self):
        """Calculate average rating from reviews. Returns 0.0 if no reviews."""
        if not self.reviews:
            return 0.0
        total_rating = sum([r.rating for r in self.reviews])
        return round(total_rating / len(self.reviews), 1)
    
    def get_rating_display(self):
        """Get rating for display. Returns 0.0 if no reviews."""
        return self.calculate_rating()


class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey("coach.id"), nullable=False)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )  # The Hirer
    sport = db.Column(db.String(100), nullable=False)
    booking_date = db.Column(db.Date, nullable=False)
    booking_time = db.Column(db.String(20), nullable=False)
    location = db.Column(db.String(255), nullable=True)
    message = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="Pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def redirect_for_user(user: User):
    """
    Central place to decide where to send a user after login / when already logged in.
    Coaches -> dashboard, Hirers -> home.
    """
    if user.role == "coach":
        return redirect(url_for("coach_dashboard"))
    return redirect(url_for("home"))


def create_slug(name, sport_str):
    first_sport = sport_str.split(",")[0] if sport_str else "coach"
    base = slugify(f"{name}-{first_sport}")
    slug = base
    counter = 2
    while Coach.query.filter_by(slug=slug).first():
        slug = f"{base}-{counter}"
        counter += 1
    return slug


# ---------------------------------
# ROUTES
# ---------------------------------
# ---------- PLANS ROUTE ----------
@app.route("/plans")
def plans():
    return render_template("pricing.html")


@app.route("/review/<int:coach_id>", methods=["POST"])
@hirer_required
def add_review(coach_id):
    coach = Coach.query.get_or_404(coach_id)

    valid_booking = Booking.query.filter_by(
        user_id=current_user.id, coach_id=coach.id, status="Confirmed"
    ).first()

    if not valid_booking:
        flash(
            "You must complete a session with this coach before leaving a review.",
            "danger",
        )
        return redirect(url_for("coach_detail", slug=coach.slug))

    rating_str = request.form.get("rating", "").strip()
    comment = request.form.get("comment", "").strip()

    # Validate rating
    try:
        rating = int(rating_str)
    except (TypeError, ValueError):
        flash("Please select a valid rating.", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))

    if rating < 1 or rating > 5:
        flash("Rating must be between 1 and 5.", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))

    # Validate comment length
    if comment and len(comment) > 2000:
        flash("Comment is too long (max 2000 characters).", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))

    existing_review = Review.query.filter_by(
        coach_id=coach.id, user_id=current_user.id
    ).first()

    if existing_review:
        existing_review.rating = rating
        existing_review.comment = sanitize_input(comment, max_length=2000)
    else:
        new_review = Review(
            coach_id=coach.id,
            user_id=current_user.id,
            rating=rating,
            comment=sanitize_input(comment, max_length=2000),
        )
        db.session.add(new_review)

    db.session.commit()

    # Calculate and update coach rating based on all reviews
    coach.rating = coach.calculate_rating()
    db.session.commit()

    flash("Review submitted successfully!", "success")
    return redirect(url_for("coach_detail", slug=coach.slug))


@app.route("/subscribe", methods=["POST"])
@rate_limit(max_requests=3, window_seconds=60)
def subscribe():
    email = request.form.get("email", "").strip().lower()

    if not email:
        flash("Please enter an email address.", "danger")
        return redirect(request.referrer or url_for("home"))

    if not validate_email(email):
        flash("Invalid email format.", "danger")
        return redirect(request.referrer or url_for("home"))

    if email:
        existing = Subscriber.query.filter_by(email=email).first()

        if existing:
            flash("You are already subscribed!", "info")
        else:
            new_sub = Subscriber(email=email)
            db.session.add(new_sub)
            db.session.commit()

            try:
                msg = Message("Welcome to the Club! 🏆", recipients=[email])
                msg.body = (
                    "Hi there,\n\n"
                    "Thanks for joining the GameChanger community! You're now on the list to receive "
                    "updates on top coaches, training tips, and exclusive offers.\n\n"
                    "Ready to level up? Find your mentor today: "
                    + url_for("coaches", _external=True)
                    + "\n\n"
                    "Best,\nThe GameChanger Team"
                )
                mail.send(msg)
            except Exception as e:
                logger.error(f"Email failed: {e}")

            flash("Thanks for subscribing! A welcome email is on its way.", "success")
    else:
        flash("Please enter a valid email.", "danger")

    return redirect(request.referrer or url_for("home"))


@app.route("/admin")
@admin_required
def admin_dashboard():

    stats = {
        "total_users": User.query.count(),
        "total_coaches": Coach.query.count(),
        "total_bookings": Booking.query.count(),
        "subscribers": Subscriber.query.count(),
        "revenue": sum(
            [b.coach.price_per_session for b in Booking.query.all() if b.coach]
        ),
    }

    recent_bookings = Booking.query.order_by(Booking.created_at.desc()).limit(10).all()
    pending_coaches = Coach.query.filter_by(is_verified=False).limit(5).all()

    return render_template(
        "admin_dashboard.html",
        stats=stats,
        bookings=recent_bookings,
        pending_coaches=pending_coaches,
    )


@app.route("/admin/verify/<int:coach_id>")
@admin_required
def admin_verify_coach(coach_id):

    coach = Coach.query.get_or_404(coach_id)
    coach.is_verified = True
    db.session.commit()
    flash(f"Verified Coach {coach.name} successfully.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/email", methods=["GET", "POST"])
@admin_required
def admin_email():

    subscribers = Subscriber.query.all()

    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        body_text = request.form.get("message", "").strip()

        # Validate inputs
        if not subject:
            flash("Subject is required.", "warning")
            return render_template("admin_email.html", subscriber_count=len(subscribers))
        
        if len(subject) > 200:
            flash("Subject is too long (max 200 characters).", "warning")
            return render_template("admin_email.html", subscriber_count=len(subscribers))

        if not body_text:
            flash("Message is required.", "warning")
            return render_template("admin_email.html", subscriber_count=len(subscribers))
        
        if len(body_text) > 10000:
            flash("Message is too long (max 10000 characters).", "warning")
            return render_template("admin_email.html", subscriber_count=len(subscribers))
        else:
            sent_count = 0
            try:
                subject_safe = sanitize_input(subject, max_length=200)
                with mail.connect() as conn:
                    for sub in subscribers:
                        msg = Message(subject_safe, recipients=[sub.email])
                        msg.body = sanitize_input(body_text, max_length=10000) + "\n\n--\nUnsubscribe: Reply with 'UNSUBSCRIBE'"
                        conn.send(msg)
                        sent_count += 1

                flash(
                    f"Successfully sent email to {sent_count} subscribers!",
                    "success",
                )
                return redirect(url_for("admin_dashboard"))

            except Exception as e:
                logger.error(f"Bulk email error: {e}")
                flash("An error occurred while sending emails.", "danger")

    return render_template("admin_email.html", subscriber_count=len(subscribers))


@app.route("/")
def home():
    top_coaches = Coach.query.filter(Coach.rating > 0).order_by(Coach.rating.desc()).limit(6).all()
    if len(top_coaches) < 6:
        zero_rating_coaches = Coach.query.filter(Coach.rating == 0.0).limit(6 - len(top_coaches)).all()
        top_coaches.extend(zero_rating_coaches)
    stats = {
        "active_impressions": "3.2k",
        "total_coaches": Coach.query.count(),
        "total_bookings": Booking.query.count(),
    }
    if not top_coaches or len(top_coaches) == 0:
        sample = [
            {
                "name": "Rahul Sharma",
                "slug": "rahul-sharma-cricket",
                "profile_image": "",
                "sport": "Cricket",
                "price_per_session": 500,
                "rating": 4.8,
                "tagline": "Batting technique & nets specialist",
                "is_verified": True,
                "city": "Mumbai"
            },
            {
                "name": "Meera Patel",
                "slug": "meera-patel-tennis",
                "profile_image": "",
                "sport": "Tennis",
                "price_per_session": 700,
                "rating": 4.7,
                "tagline": "Footwork, serve & volley coach",
                "is_verified": True,
                "city": "Pune"
            },
            {
                "name": "Aditya Rao",
                "slug": "aditya-rao-badminton",
                "profile_image": "",
                "sport": "Badminton",
                "price_per_session": 400,
                "rating": 4.6,
                "tagline": "Speed & agility trainer",
                "is_verified": False,
                "city": "Bengaluru"
            },
            {
                "name": "Priya Singh",
                "slug": "priya-singh-swimming",
                "profile_image": "",
                "sport": "Swimming",
                "price_per_session": 600,
                "rating": 4.9,
                "tagline": "Stroke correction & fitness",
                "is_verified": True,
                "city": "Chennai"
            },
            {
                "name": "Vikram Das",
                "slug": "vikram-das-football",
                "profile_image": "",
                "sport": "Football",
                "price_per_session": 450,
                "rating": 4.5,
                "tagline": "Strikers & small-sided games coach",
                "is_verified": False,
                "city": "Delhi"
            },
            {
                "name": "Ananya Roy",
                "slug": "ananya-roy-basketball",
                "profile_image": "",
                "sport": "Basketball",
                "price_per_session": 550,
                "rating": 4.6,
                "tagline": "Shooting & ball-handling coach",
                "is_verified": True,
                "city": "Kolkata"
            },
        ]
        class _S:
            def __init__(self, d):
                self.__dict__.update(d)
        top_coaches = [_S(s) for s in sample]

    return render_template("home.html", coaches=top_coaches,stats=stats, sports_list=SPORTS_LIST)

# ---------- STATIC INFO PAGES ----------
@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/careers")
def careers():
    return render_template("careers.html")

@app.route("/help")
def help_center():
    return render_template("help_center.html")

@app.route("/terms")
def terms():
    return render_template("terms.html")

@app.route("/coaches")
def coaches():
    # Pagination
    page = request.args.get("page", 1, type=int)

    # Filters
    sport_filter = request.args.get("sport", "").strip()
    city_filter = request.args.get("city", "").strip()
    price_min = request.args.get("price_min", type=int)
    price_max = request.args.get("price_max", type=int)

    query = Coach.query

    if sport_filter:
        query = query.filter(Coach.sport.ilike(f"%{sport_filter}%"))
    if city_filter:
        query = query.filter(Coach.city.ilike(f"%{city_filter}%"))
    if price_min is not None:
        query = query.filter(Coach.price_per_session >= price_min)
    if price_max is not None:
        query = query.filter(Coach.price_per_session <= price_max)

    # Order by best rating first (coaches with ratings > 0 first, then 0 ratings)
    pagination = query.order_by(Coach.rating.desc()).paginate(
        page=page, per_page=9, error_out=False
    )

    return render_template(
        "coaches.html",
        pagination=pagination,
        coaches=pagination.items,
        sports_list=SPORTS_LIST,   # for dropdown
        sport_filter=sport_filter,
        city_filter=city_filter,
        price_min=price_min,
        price_max=price_max,
    )

@app.route("/coach/availability")
@coach_required
def coach_availability():

    return render_template("coach_availability.html")


@app.route("/coach/availability/update", methods=["POST"])
@coach_required
def update_availability():

    flash("Availability schedule updated successfully!", "success")
    return redirect(url_for("coach_dashboard"))


@app.route("/coaches/<slug>")
def coach_detail(slug):
    coach = Coach.query.filter_by(slug=slug).first_or_404()
    achievements = coach.achievements.splitlines() if coach.achievements else []
    specialties = [s.strip() for s in (coach.specialties or "").split(",") if s.strip()]

    can_review = False
    if current_user.is_authenticated and current_user.role != "coach":
        booking = Booking.query.filter_by(
            user_id=current_user.id, coach_id=coach.id, status="Confirmed"
        ).first()
        if booking:
            can_review = True

    return render_template(
        "coach_detail.html",
        coach=coach,
        achievements=achievements,
        specialties=specialties,
        can_review=can_review,
    )

@app.route("/book/<int:coach_id>", methods=["POST"])
@hirer_required
def book_session(coach_id):
    coach = Coach.query.get_or_404(coach_id)
    
    # Get and validate form data
    sport = request.form.get("sport", "").strip()
    date_str = request.form.get("date", "").strip()
    time_slot = request.form.get("time", "").strip()
    message = request.form.get("message", "").strip()
    location = request.form.get("location", "").strip()

    # Validate required fields
    if not sport:
        flash("Please select a sport.", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))

    if not date_str or not time_slot:
        flash("Please select a valid date and time.", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))

    # Validate sport is in coach's sports list
    coach_sports = coach.get_sports_list()
    if sport not in coach_sports:
        flash("Invalid sport selected.", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))

    # Validate date
    date_valid, date_result = validate_date(date_str)
    if not date_valid:
        flash(date_result, "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))
    date_obj = date_result

    # Validate time
    time_valid, time_result = validate_time(time_slot)
    if not time_valid:
        flash(time_result, "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))

    # Validate message length
    if message and len(message) > 1000:
        flash("Message is too long (max 1000 characters).", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))

    # Validate location length
    if location and len(location) > 255:
        flash("Location is too long (max 255 characters).", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))

    existing_booking = Booking.query.filter_by(
        coach_id=coach.id,
        booking_date=date_obj,
        booking_time=time_slot
    ).filter(Booking.status.in_(["Confirmed", "Payment Pending"])).first()

    if existing_booking:
        flash("This time slot is already booked. Please choose another.", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))

    initial_status = "Payment Pending"
    if coach.price_per_session == 0:
        initial_status = "Confirmed"

    new_booking = Booking(
        coach_id=coach.id,
        user_id=current_user.id,
        sport=sanitize_input(sport),
        booking_date=date_obj,
        booking_time=time_result,
        message=sanitize_input(message, max_length=1000),
        location=sanitize_input(location, max_length=255),
        status=initial_status, 
    )

    db.session.add(new_booking)
    db.session.commit()

    if coach.price_per_session == 0:
        flash("Booking confirmed!", "success")
        return redirect(url_for("coach_dashboard"))

    # Create Stripe Session for paid coaches
    try:
        checkout_session = stripe.checkout.Session.create(
            mode="payment",
            customer_email=current_user.email, # Pre-fill user email
            line_items=[{
                'price_data': {
                    'currency': 'inr',
                    'unit_amount': int(coach.price_per_session * 100),
                    'product_data': {
                        'name': f"Training with {coach.name}",
                        'description': f"{sport} Session on {date_str} at {time_slot}",
                    },
                },
                'quantity': 1,
            }],
            metadata={
                'booking_id': new_booking.id, 
                'type': 'coach_booking'
            },
            success_url=url_for('coach_dashboard', _external=True) + "?payment=success",
            cancel_url=url_for('coach_detail', slug=coach.slug, _external=True) + "?payment=cancelled",
        )
        return redirect(checkout_session.url, code=303)

    except Exception as e:
        logger.exception("Stripe Error")
        db.session.delete(new_booking)
        db.session.commit()
        flash("Error initializing payment. Please try again.", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))
@app.route("/booking/<int:booking_id>/status", methods=["POST"])
@coach_required
def update_booking_status(booking_id):
    booking = Booking.query.get_or_404(booking_id)

    if not current_user.coach_profile:
        flash("Coach profile not found.", "danger")
        return redirect(url_for("coach_dashboard"))

    if booking.coach_id != current_user.coach_profile.id:
        flash("You are not allowed to modify this booking.", "danger")
        return redirect(url_for("coach_dashboard"))

    new_status = request.form.get("status", "").strip()

    if new_status not in ["Confirmed", "Rejected"]:
        flash("Invalid status update.", "danger")
        return redirect(url_for("coach_dashboard"))

    booking.status = new_status
    db.session.commit()

    try:
        if booking.student and booking.student.email:
            if new_status == "Confirmed":
                subject = "Your GameChanger booking was confirmed 🎉"
                body = (
                    f"Hi {booking.student.name},\n\n"
                    f"Good news! Your booking with Coach {booking.coach.name} has been CONFIRMED.\n\n"
                    f"Sport: {booking.sport}\n"
                    f"Date: {booking.booking_date.strftime('%d %b %Y')}\n"
                    f"Time: {booking.booking_time}\n"
                    f"Location: {booking.location or 'Not specified'}\n\n"
                    "You can see this session under 'My Schedule' in your dashboard.\n\n"
                    "- GameChanger"
                )
            else:
                subject = "Your GameChanger booking was updated"
                body = (
                    f"Hi {booking.student.name},\n\n"
                    f"Your booking with Coach {booking.coach.name} has been marked as REJECTED.\n\n"
                    f"Sport: {booking.sport}\n"
                    f"Date: {booking.booking_date.strftime('%d %b %Y')}\n"
                    f"Time: {booking.booking_time}\n\n"
                    "You can try booking another slot or a different coach on GameChanger.\n\n"
                    "- GameChanger"
                )

            msg = Message(subject, recipients=[booking.student.email])
            msg.body = body
            mail.send(msg)
    except Exception as e:
        logger.error(f"Hirer notification email error: {e}")

    # Flash messages for coach
    if new_status == "Confirmed":
        flash("Booking confirmed. The student will see it as Confirmed in their dashboard.", "success")
    else:
        flash("Booking marked as Rejected.", "info")

    return redirect(url_for("coach_dashboard"))


@app.route("/register", methods=["GET", "POST"])
@rate_limit(max_requests=5, window_seconds=300)
def register():
    if current_user.is_authenticated:
        return redirect_for_user(current_user)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "hirer")
        org_type = request.form.get("org_type", "individual")

        # Validate name
        name_valid, name_msg = validate_name(name)
        if not name_valid:
            flash(name_msg, "danger")
            return render_template("register.html")

        # Validate email
        if not validate_email(email):
            flash("Invalid email format.", "danger")
            return render_template("register.html")

        # Validate password
        password_valid, password_msg = validate_password(password)
        if not password_valid:
            flash(password_msg, "danger")
            return render_template("register.html")

        # Validate role
        if role not in ["hirer", "coach"]:
            flash("Invalid role selected.", "danger")
            return render_template("register.html")

        # Check if email exists
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return render_template("register.html")

        is_org = False
        if role == "hirer" and org_type == "organization":
            is_org = True

        try:
            user = User(name=sanitize_input(name), email=email, role=role, is_organization=is_org)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            login_user(user)
            flash(f"Welcome, {name}!", "success")

            if role == "coach":
                return redirect(url_for("coach_dashboard"))
            else:
                if is_org:
                    return redirect(url_for("plans"))
                return redirect(url_for("home"))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {e}")
            flash("An error occurred during registration. Please try again.", "danger")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@rate_limit(max_requests=5, window_seconds=300)
def login():
    if current_user.is_authenticated:
        return redirect_for_user(current_user)

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # Validate email format
        if not validate_email(email):
            flash("Invalid email format.", "danger")
            return render_template("login.html")

        # Validate password presence
        if not password:
            flash("Password is required.", "danger")
            return render_template("login.html")

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            logger.info(f"User {user.id} logged in successfully")
            return redirect_for_user(user)
        else:
            logger.warning(f"Failed login attempt for email: {email}")
            flash("Invalid email or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route("/send_otp", methods=["POST"])
@login_required
def send_otp():
    try:
        otp = "".join(random.choices(string.digits, k=6))
        session["verification_otp"] = otp
        msg = Message(
            "Verify your Game Changer Account", recipients=[current_user.email]
        )
        msg.body = (
            f"Hello {current_user.name},\n\n"
            f"Your Verification OTP is: {otp}\n\n"
            "Do not share this with anyone."
        )
        mail.send(msg)
        return {"status": "success", "message": "OTP sent to " + current_user.email}
    except Exception as e:
        logger.error(f"OTP email error: {e}")
        return {
            "status": "error",
            "message": "Failed to send email. Check app config.",
        }


@app.route("/verify/coach", methods=["POST"])
@login_required
def verify_coach():
    user_code = request.form.get("code")
    stored_otp = session.get("verification_otp")
    if stored_otp and user_code == stored_otp:
        if current_user.coach_profile:
            current_user.coach_profile.is_verified = True
            db.session.commit()
            session.pop("verification_otp", None)
            flash("Success! You are now a Verified Coach.", "success")
        else:
            flash("Please create a coach profile first.", "warning")
    else:
        flash("Invalid OTP. Please try again.", "danger")
    return redirect(url_for("coach_dashboard"))


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def coach_dashboard():
    coach = current_user.coach_profile

    # Booking filter: all / pending / confirmed / rejected / upcoming
    booking_filter = request.args.get("filter", "all").lower()

    def apply_booking_filter(query):
        today = datetime.now().date()
        if booking_filter == "pending":
            return query.filter_by(status="Pending")
        if booking_filter == "confirmed":
            return query.filter_by(status="Confirmed")
        if booking_filter == "rejected":
            return query.filter_by(status="Rejected")
        if booking_filter == "upcoming":
            return query.filter(Booking.booking_date >= today)
        return query

    my_query = Booking.query.filter_by(user_id=current_user.id)
    my_query = apply_booking_filter(my_query)
    my_bookings = my_query.order_by(Booking.booking_date.desc()).all()

    received_bookings = []
    if coach:
        received_query = Booking.query.filter_by(coach_id=coach.id)
        received_query = apply_booking_filter(received_query)
        received_bookings = received_query.order_by(Booking.booking_date.desc()).all()

    # Calculate stats for dashboard
    stats = {}
    if coach:
        stats['total_bookings'] = Booking.query.filter_by(coach_id=coach.id).count()
        stats['confirmed_bookings'] = Booking.query.filter_by(coach_id=coach.id, status='Confirmed').count()
        stats['pending_bookings'] = Booking.query.filter_by(coach_id=coach.id, status='Pending').count()
        stats['total_reviews'] = Review.query.filter_by(coach_id=coach.id).count()
        stats['rating'] = coach.get_rating_display()
    else:
        stats['total_bookings'] = len(my_bookings)
        stats['confirmed_bookings'] = len([b for b in my_bookings if b.status == 'Confirmed'])
        stats['pending_bookings'] = len([b for b in my_bookings if b.status == 'Pending'])
        stats['total_reviews'] = 0
        stats['rating'] = 0.0
    
    context = {
        "coach": coach,
        "sports_list": SPORTS_LIST,
        "my_bookings": my_bookings,
        "received_bookings": received_bookings,
        "booking_filter": booking_filter,
        "stats": stats,
    }

    if request.method == "POST":
        if current_user.role != "coach":
            flash("Only coaches can update profile settings.", "danger")
            return redirect(url_for("coach_dashboard"))

        name = request.form.get("name", "").strip()
        tagline = request.form.get("tagline", "").strip()
        achievements = request.form.get("achievements", "").strip()
        specialties = request.form.get("specialties", "").strip()
        pincode = request.form.get("pincode", "").strip()
        state = request.form.get("state", "").strip()
        city = request.form.get("city", "").strip()
        exp_raw = request.form.get("experience_years", "").strip()
        age_raw = request.form.get("age", "").strip()
        phone = request.form.get("phone", "").strip()
        travel_raw = request.form.get("travel_radius", "").strip()

        # Validate name
        name_valid, name_msg = validate_name(name)
        if not name_valid:
            flash(name_msg, "danger")
            return render_template("dashboard_coach.html", **context)

        # Validate city
        if not city or len(city.strip()) < 2:
            flash("City is required and must be at least 2 characters.", "danger")
            return render_template("dashboard_coach.html", **context)

        # Validate phone if provided
        if phone:
            phone_valid, phone_msg = validate_phone(phone)
            if not phone_valid:
                flash(phone_msg, "danger")
                return render_template("dashboard_coach.html", **context)

        # Validate numeric fields
        try:
            exp = int(exp_raw) if exp_raw else 0
            if exp < 0 or exp > 100:
                flash("Experience years must be between 0 and 100.", "danger")
                return render_template("dashboard_coach.html", **context)
            
            age = int(age_raw) if age_raw else 0
            if age < 0 or age > 120:
                flash("Age must be between 0 and 120.", "danger")
                return render_template("dashboard_coach.html", **context)
            
            travel_radius = int(travel_raw) if travel_raw else 0
            if travel_radius < 0 or travel_radius > 1000:
                flash("Travel radius must be between 0 and 1000 km.", "danger")
                return render_template("dashboard_coach.html", **context)
        except ValueError:
            flash("Age/Experience/Travel radius must be valid numbers.", "danger")
            return render_template("dashboard_coach.html", **context)

        selected_sports = request.form.getlist("sports")
        if not selected_sports:
            flash("Please select at least one sport.", "danger")
            return render_template("dashboard_coach.html", **context)

        # Validate sports are in allowed list
        for sport in selected_sports:
            if sport not in SPORTS_LIST:
                flash(f"Invalid sport selected: {sport}", "danger")
                return render_template("dashboard_coach.html", **context)

        prices_dict = {}
        for sport in selected_sports:
            price_input = request.form.get(f"price_{sport}", "").strip()
            if price_input:
                price_valid, price_result = validate_price(price_input)
                if price_valid:
                    prices_dict[sport] = price_result
                else:
                    flash(f"Invalid price for {sport}: {price_result}", "danger")
                    return render_template("dashboard_coach.html", **context)
            else:
                prices_dict[sport] = 0

        sports_str = ",".join(selected_sports)
        prices_json = json.dumps(prices_dict)
        starting_price = min(prices_dict.values()) if prices_dict else 0

        if not name or not city or not selected_sports:
            flash("Name, City and at least one Sport are required.", "danger")
            return render_template("dashboard_coach.html", **context)

        image_filename = coach.profile_image if coach else "default_coach.jpg"
        if "profile_image" in request.files:
            file = request.files["profile_image"]
            if file and file.filename != "":
                file_valid, file_msg = validate_file_upload(file)
                if file_valid:
                    ext = file.filename.rsplit(".", 1)[1].lower()
                    new_filename = secure_filename(
                        f"coach_{current_user.id}_{int(datetime.now().timestamp())}.{ext}"
                    )
                    try:
                        file.save(os.path.join(app.config["UPLOAD_FOLDER"], new_filename))
                        image_filename = new_filename
                    except Exception as e:
                        logger.error(f"File upload error: {e}")
                        flash("Error uploading image. Please try again.", "danger")
                        return render_template("dashboard_coach.html", **context)
                else:
                    flash(file_msg, "danger")
                    return render_template("dashboard_coach.html", **context)

        # Sanitize text inputs
        name_safe = sanitize_input(name, max_length=120)
        tagline_safe = sanitize_input(tagline, max_length=255)
        achievements_safe = sanitize_input(achievements, max_length=5000)
        specialties_safe = sanitize_input(specialties, max_length=1000)
        city_safe = sanitize_input(city, max_length=120)
        state_safe = sanitize_input(state, max_length=100)
        pincode_safe = sanitize_input(pincode, max_length=10)
        phone_safe = sanitize_input(phone, max_length=15)

        if coach is None:
            slug = create_slug(name_safe, sports_str)
            coach = Coach(
                user_id=current_user.id,
                slug=slug,
                name=name_safe,
                sport=sports_str,
                sports_prices=prices_json,
                city=city_safe,
                state=state_safe,
                pincode=pincode_safe,
                price_per_session=starting_price,
                experience_years=exp,
                age=age,
                phone=phone_safe,
                tagline=tagline_safe,
                specialties=specialties_safe,
                profile_image=image_filename,
                achievements=achievements_safe,
                travel_radius=travel_radius,
                rating=0.0,
            )
            db.session.add(coach)
        else:
            coach.name = name_safe
            coach.sport = sports_str
            coach.sports_prices = prices_json
            coach.city = city_safe
            coach.state = state_safe
            coach.pincode = pincode_safe
            coach.price_per_session = starting_price
            coach.experience_years = exp
            coach.age = age
            coach.phone = phone_safe
            coach.tagline = tagline_safe
            coach.specialties = specialties_safe
            coach.profile_image = image_filename
            coach.achievements = achievements_safe
            coach.travel_radius = travel_radius

        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for("coach_dashboard"))

    return render_template("dashboard_coach.html", **context)

# ---------- STRIPE CHECKOUT & WEBHOOK ROUTES ----------
@app.route("/create-checkout-session/<plan>", methods=["POST", "GET"])
@login_required
def create_checkout_session(plan):

    if not STRIPE_SECRET_KEY:
        flash("Stripe is not configured.", "danger")
        return redirect(url_for("plans"))

    # Load Stripe Price IDs from environment
    PRICE_COACH = os.getenv("STRIPE_PRICE_COACH_PRO")
    PRICE_ACADEMY = os.getenv("STRIPE_PRICE_ACADEMY_PRO")

    price_map = {
        "coach_premium": PRICE_COACH,
        "academy_pro": PRICE_ACADEMY,
    }

    if plan not in price_map or price_map[plan] is None:
        flash("Invalid plan configuration.", "danger")
        return redirect(url_for("plans"))

    selected_price_id = price_map[plan]

    try:
        # Create or reuse Stripe Customer for current user
        if current_user.stripe_customer_id:
            customer_id = current_user.stripe_customer_id
        else:
            customer = stripe.Customer.create(email=current_user.email, name=current_user.name)
            customer_id = customer["id"]
            current_user.stripe_customer_id = customer_id
            db.session.commit()

        checkout_session = stripe.checkout.Session.create(
            mode="payment",
            customer=customer_id,
            line_items=[
                {
                    "price": selected_price_id,
                    "quantity": 1,
                }
            ],
            success_url=url_for("plans", _external=True) + "?payment=success&session_id={CHECKOUT_SESSION_ID}",
            cancel_url=url_for("plans", _external=True) + "?payment=cancel",
            client_reference_id=str(current_user.id),
        )

        logger.info(f"Created Stripe Checkout Session {checkout_session['id']} for user {current_user.id}")
        return redirect(checkout_session.url, code=303)

    except Exception as e:
        logger.exception("Failed to create Stripe Checkout")
        flash("Payment process failed.", "danger")
        return redirect(url_for("plans"))

@app.route("/stripe_webhook", methods=["POST"])
def stripe_webhook():
    """Webhook endpoint for Stripe events. Verifies signature and performs idempotent handling."""
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get("Stripe-Signature", None)

    if not STRIPE_WEBHOOK_SECRET:
        logger.error("STRIPE_WEBHOOK_SECRET not configured; rejecting webhook.")
        return ("Webhook not configured", 400)

    try:
        event = stripe.Webhook.construct_event(payload=payload, sig_header=sig_header, secret=STRIPE_WEBHOOK_SECRET)
    except ValueError:
        # Invalid payload
        logger.warning("Invalid payload received on /stripe_webhook")
        return ("Invalid payload", 400)
    except stripe.error.SignatureVerificationError:
        logger.warning("Invalid signature on /stripe_webhook")
        return ("Invalid signature", 400)
    except Exception as e:
        logger.exception("Unexpected error while verifying webhook")
        return ("Webhook verification error", 400)

    event_id = event.get("id")
    if StripeEvent.query.filter_by(event_id=event_id).first():
        logger.info(f"Webhook event {event_id} already processed — skipping.")
        return ("Already processed", 200)

    try:
        db.session.add(StripeEvent(event_id=event_id))
        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.exception("Could not store StripeEvent; aborting to avoid duplicate work.")
        return ("DB error", 500)
    try:
        if event["type"] == "checkout.session.completed":
            session_obj = event["data"]["object"]
            metadata = session_obj.get("metadata", {})
            
            if metadata.get("type") is None:
                client_ref = session_obj.get("client_reference_id")
                customer_id = session_obj.get("customer")
                if client_ref:
                    user = User.query.get(int(client_ref))
                    if user:
                        user.stripe_customer_id = customer_id
                        user.stripe_session_id = session_obj.get("id")
                        db.session.commit()

            elif metadata.get("type") == "coach_booking":
                booking_id = metadata.get("booking_id")
                if booking_id:
                    booking = Booking.query.get(booking_id)
                    if booking:
                        booking.status = "Confirmed"
                        db.session.commit()
                        logger.info(f"Booking {booking_id} confirmed via Stripe.")
                        send_booking_confirmation_emails(booking) 

    except Exception:
        db.session.rollback()
        logger.exception("Error processing stripe event")
        return ("Processing error", 500)
def send_booking_confirmation_emails(booking):
    """Sends confirmation emails to both Coach and Student"""
    try:
        # Email to Coach
        if booking.coach.user.email:
            msg_coach = Message(
                "New Paid Booking Confirmed! 💰",
                recipients=[booking.coach.user.email]
            )
            msg_coach.body = (
                f"Hi {booking.coach.name},\n\n"
                f"Payment received! You have a confirmed session with {booking.student.name}.\n"
                f"Date: {booking.booking_date}\nTime: {booking.booking_time}\n\n"
                "- GameChanger Team"
            )
            mail.send(msg_coach)

        # Email to Student
        if booking.student.email:
            msg_student = Message(
                "Booking Confirmed! ✅",
                recipients=[booking.student.email]
            )
            msg_student.body = (
                f"Hi {booking.student.name},\n\n"
                f"Your payment was successful. You are booked with {booking.coach.name}!\n"
                f"Date: {booking.booking_date}\nTime: {booking.booking_time}\n\n"
                "- GameChanger Team"
            )
            mail.send(msg_student)
            
    except Exception as e:
        logger.error(f"Failed to send confirmation emails: {e}")
# ERROR HANDLERS
# ---------------------------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("404.html"), 500

# ---------- GOOGLE SHEETS INTEGRATION ----------
def save_to_google_sheets(name, phone, email, needs, source="contact_form"):
    """Save user details to Google Sheets."""
    if not GOOGLE_SHEETS_AVAILABLE:
        logger.warning("Google Sheets not available - skipping save")
        return False
    
    try:
        credentials_json = os.getenv("GOOGLE_SHEETS_CREDENTIALS")
        sheet_id = os.getenv("GOOGLE_SHEET_ID")
        
        if not credentials_json or not sheet_id:
            logger.warning("Google Sheets credentials not configured")
            return False
        
        # Parse credentials JSON string
        creds_dict = json.loads(credentials_json)
        creds = Credentials.from_service_account_info(creds_dict, scopes=[
            'https://www.googleapis.com/auth/spreadsheets',
            'https://www.googleapis.com/auth/drive'
        ])
        
        client = gspread.authorize(creds)
        sheet = client.open_by_key(sheet_id).sheet1
        
        row = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            name,
            phone or "",
            email or "",
            needs or "",
            source
        ]
        sheet.append_row(row)
        logger.info(f"Saved user details to Google Sheets: {name}")
        return True
        
    except Exception as e:
        logger.error(f"Error saving to Google Sheets: {e}")
        return False

# ---------- CONTACT/LEAD CAPTURE ROUTE ----------
@app.route("/api/contact", methods=["POST"])
@rate_limit(max_requests=5, window_seconds=60)
def contact_submit():
    """Handle contact form submissions."""
    if not request.is_json:
        return jsonify({"success": False, "message": "Content-Type must be application/json"}), 400
    
    data = request.get_json()
    
    # Validate JSON structure
    json_valid, json_msg = validate_json_input(data, required_fields=["name"])
    if not json_valid:
        return jsonify({"success": False, "message": json_msg}), 400
    
    name = data.get("name", "").strip()
    phone = data.get("phone", "").strip()
    email = data.get("email", "").strip()
    needs = data.get("needs", "").strip()
    source = data.get("source", "contact_form")
    
    # Validate name
    name_valid, name_msg = validate_name(name)
    if not name_valid:
        return jsonify({"success": False, "message": name_msg}), 400
    
    # Validate email if provided
    if email and not validate_email(email):
        return jsonify({"success": False, "message": "Invalid email format"}), 400
    
    # Validate phone if provided
    if phone:
        phone_valid, phone_msg = validate_phone(phone)
        if not phone_valid:
            return jsonify({"success": False, "message": phone_msg}), 400
    
    # Validate needs length
    if needs and len(needs) > 2000:
        return jsonify({"success": False, "message": "Needs field is too long (max 2000 characters)"}), 400
    
    # Save to Google Sheets
    # Sanitize inputs before saving
    name_safe = sanitize_input(name, max_length=120)
    phone_safe = sanitize_input(phone, max_length=15) if phone else ""
    email_safe = email.lower() if email else ""
    needs_safe = sanitize_input(needs, max_length=2000) if needs else ""
    
    save_to_google_sheets(name_safe, phone_safe, email_safe, needs_safe, source)
    return jsonify({
        "success": True,
        "message": "Thank you! We'll get back to you soon."
    })

# ---------- CHATBOT ROUTE ----------
@app.route("/api/chatbot", methods=["POST"])
@rate_limit(max_requests=20, window_seconds=60)
def chatbot():
    """Handle chatbot queries."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    
    data = request.get_json()
    
    # Validate JSON structure
    json_valid, json_msg = validate_json_input(data, required_fields=["query"])
    if not json_valid:
        return jsonify({"error": json_msg}), 400
    
    query = data.get("query", "").strip()
    
    # Validate query length
    if not query:
        return jsonify({"error": "Query is required"}), 400
    
    if len(query) > 500:
        return jsonify({"error": "Query is too long (max 500 characters)"}), 400
    
    query = query.lower()
    
    if any(keyword in query for keyword in ["which coach", "choose coach", "select coach", "find coach", "coach recommendation", "best coach"]):
        total_coaches = Coach.query.count()
        verified_coaches = Coach.query.filter_by(is_verified=True).count()
        top_rated = Coach.query.filter(Coach.rating > 0).order_by(Coach.rating.desc()).limit(3).all()
        
        response = "Here's how to choose the right coach for you:\n\n"
        response += "1. **Sport & Expertise**: Filter by your sport (Cricket, Football, Badminton, etc.)\n"
        response += "2. **Location**: Choose coaches in your city or check their travel radius\n"
        response += "3. **Budget**: Compare prices per session (₹400-₹700+ range)\n"
        response += "4. **Ratings**: Look for verified coaches with high ratings (4.5+)\n"
        response += "5. **Experience**: Check years of experience and achievements\n\n"
        
        if top_rated:
            response += "**Top Rated Coaches:**\n"
            for coach in top_rated:
                response += f"• {coach.name} - {coach.sport.split(',')[0]} (★{coach.rating}) - ₹{coach.price_per_session}/session\n"
            response += "\n"
        
        response += f"We have {total_coaches} coaches available, with {verified_coaches} verified professionals.\n\n"
        response += "**Tip**: Use filters on the 'Find a Mentor' page to narrow down by sport, city, and price range!"
        
        return jsonify({"response": response, "type": "coach_selection"})
    
    elif any(keyword in query for keyword in ["pricing", "price", "cost", "fee", "how much", "prices", "subscription", "plan"]):
        coaches_with_price = Coach.query.filter(Coach.price_per_session > 0).all()
        avg_price = sum(c.price_per_session for c in coaches_with_price) / len(coaches_with_price) if coaches_with_price else 500
        min_price = min((c.price_per_session for c in coaches_with_price), default=400)
        max_price = max((c.price_per_session for c in coaches_with_price), default=700)
        
        response = "**Pricing Information:**\n\n"
        response += "**Session-Based Pricing:**\n"
        response += f"• Coaches set their own rates: ₹{int(min_price)} - ₹{int(max_price)} per session (average ₹{int(avg_price)})\n"
        response += "• You pay per session when booking\n"
        response += "• Free coaches are also available (₹0/session)\n\n"
        
        response += "**Premium Plans (One-Time Payment):**\n"
        response += "• **Coach Pro**: ₹1,999 - Verified badge, priority search, unlimited bookings, dashboard insights\n"
        response += "• **Academy Pro**: ₹4,999 - For academies: hire multiple coaches, bulk management, team dashboard\n\n"
        
        response += "💡 **Note**: Premium plans are one-time payments, not monthly subscriptions. Visit the Pricing page for details!"
        
        return jsonify({"response": response, "type": "pricing"})
    
    elif any(keyword in query for keyword in ["how booking", "booking works", "how to book", "book session", "booking process", "how do i book"]):
        response = "**How Booking Works:**\n\n"
        response += "**Step 1: Find a Coach**\n"
        response += "• Browse coaches on the 'Find a Mentor' page\n"
        response += "• Filter by sport, city, and budget\n"
        response += "• Click on a coach to view their profile\n\n"
        
        response += "**Step 2: Book a Session**\n"
        response += "• Select your sport from the coach's offerings\n"
        response += "• Choose a date and time slot\n"
        response += "• Add location and any special message\n"
        response += "• Click 'Book Session'\n\n"
        
        response += "**Step 3: Payment**\n"
        response += "• For paid coaches: Complete payment via Stripe (secure checkout)\n"
        response += "• For free coaches: Booking is confirmed immediately\n"
        response += "• You'll receive email confirmation\n\n"
        
        response += "**Step 4: Session**\n"
        response += "• Coach confirms the booking\n"
        response += "• Attend your session at the agreed location\n"
        response += "• After completion, you can leave a review\n\n"
        
        response += "**Note**: You need to be logged in as a student/hirer to book. Coaches cannot book their own sessions."
        
        return jsonify({"response": response, "type": "booking"})
    
    elif any(keyword in query for keyword in ["contact", "get in touch", "reach out", "connect", "help me", "interested"]):
        response = "I'd love to help! Please share your details:\n\n"
        response += "**Quick Contact Form**\n"
        response += "Fill in your name, phone number, and what you're looking for, and we'll get back to you!\n\n"
        response += "Or you can ask me:\n"
        response += "• 'Which coach should I choose?'\n"
        response += "• 'Pricing?'\n"
        response += "• 'How booking works?'"
        
        return jsonify({
            "response": response,
            "type": "contact",
            "show_contact_form": True
        })
    
    else:
        response = "I can help you with:\n\n"
        response += "• **Coach Selection**: Ask 'Which coach should I choose?'\n"
        response += "• **Pricing**: Ask 'What are the prices?' or 'Pricing?'\n"
        response += "• **Booking**: Ask 'How does booking work?'\n"
        response += "• **Contact**: Ask 'I want to get in touch' or 'Contact us'\n\n"
        response += "Try asking one of these questions!"
        
        return jsonify({"response": response, "type": "general"})

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=os.getenv("FLASK_DEBUG", "False").lower() == "true")