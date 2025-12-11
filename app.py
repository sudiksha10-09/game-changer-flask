import os
import json
import random
import string
from datetime import datetime
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    session,
)
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

load_dotenv()
# ---------- STRIPE CONFIG & LOGGING ----------
import logging
import stripe

# Basic logging to stdout for Render / local visibility
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Stripe environment vars (set these in .env locally, and in Render secrets in production)
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")  # set locally to: STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY")  # pk_test_...
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")  # set from Stripe dashboard (test webhook secret)

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
app.config["SECRET_KEY"] = "dev-secret-key-change-this"

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
    rating = db.Column(db.Float, default=4.5)
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
@login_required
def add_review(coach_id):
    coach = Coach.query.get_or_404(coach_id)

    if current_user.role == "coach":
        flash("Coaches cannot leave reviews.", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))

    valid_booking = Booking.query.filter_by(
        user_id=current_user.id, coach_id=coach.id, status="Confirmed"
    ).first()

    if not valid_booking:
        flash(
            "You must complete a session with this coach before leaving a review.",
            "danger",
        )
        return redirect(url_for("coach_detail", slug=coach.slug))

    rating_str = request.form.get("rating")
    comment = request.form.get("comment", "").strip()

    try:
        rating = int(rating_str)
    except (TypeError, ValueError):
        flash("Please select a valid rating.", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))

    if rating < 1 or rating > 5:
        flash("Rating must be between 1 and 5.", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))

    existing_review = Review.query.filter_by(
        coach_id=coach.id, user_id=current_user.id
    ).first()

    if existing_review:
        existing_review.rating = rating
        existing_review.comment = comment
    else:
        new_review = Review(
            coach_id=coach.id,
            user_id=current_user.id,
            rating=rating,
            comment=comment,
        )
        db.session.add(new_review)

    db.session.commit()

    all_reviews = Review.query.filter_by(coach_id=coach.id).all()
    if all_reviews:
        avg_rating = sum([r.rating for r in all_reviews]) / len(all_reviews)
        coach.rating = round(avg_rating, 1)
        db.session.commit()

    flash("Review submitted successfully!", "success")
    return redirect(url_for("coach_detail", slug=coach.slug))


@app.route("/subscribe", methods=["POST"])
def subscribe():
    email = request.form.get("email")

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
                print(f"Email failed: {e}")

            flash("Thanks for subscribing! A welcome email is on its way.", "success")
    else:
        flash("Please enter a valid email.", "danger")

    return redirect(request.referrer or url_for("home"))


@app.route("/admin")
@login_required
def admin_dashboard():
    if current_user.email != app.config["MAIL_USERNAME"]:
        flash("Access Denied: You are not the Super Admin.", "danger")
        return redirect(url_for("home"))

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
@login_required
def admin_verify_coach(coach_id):
    if current_user.email != app.config["MAIL_USERNAME"]:
        flash("Access Denied: Admin only.", "danger")
        return redirect(url_for("home"))

    coach = Coach.query.get_or_404(coach_id)
    coach.is_verified = True
    db.session.commit()
    flash(f"Verified Coach {coach.name} successfully.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/email", methods=["GET", "POST"])
@login_required
def admin_email():
    if current_user.email != app.config["MAIL_USERNAME"]:
        flash("Access Denied: Admin only.", "danger")
        return redirect(url_for("home"))

    subscribers = Subscriber.query.all()

    if request.method == "POST":
        subject = request.form.get("subject")
        body_text = request.form.get("message")

        if not subject or not body_text:
            flash("Please fill in both subject and message.", "warning")
        else:
            sent_count = 0
            try:
                with mail.connect() as conn:
                    for sub in subscribers:
                        msg = Message(subject, recipients=[sub.email])
                        msg.body = body_text + "\n\n--\nUnsubscribe: Reply with 'UNSUBSCRIBE'"
                        conn.send(msg)
                        sent_count += 1

                flash(
                    f"Successfully sent email to {sent_count} subscribers!",
                    "success",
                )
                return redirect(url_for("admin_dashboard"))

            except Exception as e:
                print(f"Bulk email error: {e}")
                flash("An error occurred while sending emails.", "danger")

    return render_template("admin_email.html", subscriber_count=len(subscribers))


@app.route("/")
def home():
    top_coaches = Coach.query.order_by(Coach.rating.desc()).limit(3).all()
    return render_template("home.html", coaches=top_coaches)

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

    # Order by best rating first
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
@login_required
def coach_availability():
    if current_user.role != "coach":
        flash("Access denied.", "danger")
        return redirect(url_for("home"))

    return render_template("coach_availability.html")


@app.route("/coach/availability/update", methods=["POST"])
@login_required
def update_availability():
    if current_user.role != "coach":
        flash("Access denied.", "danger")
        return redirect(url_for("home"))

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
@login_required
def book_session(coach_id):
    coach = Coach.query.get_or_404(coach_id)

    # 1. Validation Logic (Same as before)
    if current_user.role != "hirer":
        flash("Only hirers can book sessions.", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))
    date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()

    # --- NEW: DOUBLE BOOKING CHECK ---
    existing_booking = Booking.query.filter_by(
        coach_id=coach.id,
        booking_date=date_obj,
        booking_time=time_slot
    ).filter(Booking.status.in_(["Confirmed", "Payment Pending"])).first()

    if existing_booking:
        flash("This time slot is already booked. Please choose another.", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))
    sport = request.form.get("sport")
    date_str = request.form.get("date")
    time_slot = request.form.get("time")
    message = request.form.get("message")
    location = request.form.get("location")

    if not date_str or not time_slot:
        flash("Please select a valid date and time.", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))

    try:
        date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
        # ... (Keep your existing date validation logic here) ...
    except ValueError:
        flash("Invalid date format.", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))

    # 2. Save Booking as "Payment Pending"
    # We save it NOW so we have an ID to send to Stripe
    initial_status = "Payment Pending"
    
    # If coach is free, we can just confirm immediately (optional logic)
    if coach.price_per_session == 0:
        initial_status = "Confirmed"

    new_booking = Booking(
        coach_id=coach.id,
        user_id=current_user.id,
        sport=sport,
        booking_date=date_obj,
        booking_time=time_slot,
        message=message,
        location=location,
        status=initial_status, 
    )

    db.session.add(new_booking)
    db.session.commit()

    # 3. If Coach is Free, skip Stripe
    if coach.price_per_session == 0:
        # Send emails manually here or refactor email logic into a function
        flash("Booking confirmed!", "success")
        return redirect(url_for("coach_dashboard"))

    # 4. If Coach is Paid, Create Stripe Session (Dynamic Price)
    try:
        checkout_session = stripe.checkout.Session.create(
            mode="payment",
            customer_email=current_user.email, # Pre-fill user email
            line_items=[{
                'price_data': {
                    'currency': 'inr',
                    # PRICE CALCULATION: Stripe expects Paisa (Multiply by 100)
                    'unit_amount': int(coach.price_per_session * 100),
                    'product_data': {
                        'name': f"Training with {coach.name}",
                        'description': f"{sport} Session on {date_str} at {time_slot}",
                    },
                },
                'quantity': 1,
            }],
            # CRITICAL: Pass the Booking ID so Webhook knows what to update
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
        # If stripe fails, delete the pending booking so it doesn't clutter DB
        db.session.delete(new_booking)
        db.session.commit()
        flash("Error initializing payment. Please try again.", "danger")
        return redirect(url_for("coach_detail", slug=coach.slug))
@app.route("/booking/<int:booking_id>/status", methods=["POST"])
@login_required
def update_booking_status(booking_id):
    booking = Booking.query.get_or_404(booking_id)

    # Only the correct coach can change status
    if current_user.role != "coach" or not current_user.coach_profile:
        flash("Access denied.", "danger")
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

    # --- Email notification to hirer (student) ---
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
        print("Hirer notification email error:", e)

    # Flash messages for coach
    if new_status == "Confirmed":
        flash("Booking confirmed. The student will see it as Confirmed in their dashboard.", "success")
    else:
        flash("Booking marked as Rejected.", "info")

    return redirect(url_for("coach_dashboard"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect_for_user(current_user)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "hirer")
        org_type = request.form.get("org_type", "individual")

        is_org = False
        if role == "hirer" and org_type == "organization":
            is_org = True

        if not name or not email or not password:
            flash("Fill all fields.", "danger")
        elif User.query.filter_by(email=email).first():
            flash("Email taken.", "danger")
        else:
            user = User(name=name, email=email, role=role, is_organization=is_org)
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

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect_for_user(current_user)

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect_for_user(user)
        else:
            flash("Invalid credentials.", "danger")
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
        print(e)
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

    context = {
        "coach": coach,
        "sports_list": SPORTS_LIST,
        "my_bookings": my_bookings,
        "received_bookings": received_bookings,
        "booking_filter": booking_filter,
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

        try:
            exp = int(exp_raw) if exp_raw else 0
            age = int(age_raw) if age_raw else 0
            travel_radius = int(travel_raw) if travel_raw else 0
        except ValueError:
            flash("Age/Experience/Travel radius must be numbers.", "danger")
            return render_template("dashboard_coach.html", **context)

        selected_sports = request.form.getlist("sports")
        prices_dict = {}
        for sport in selected_sports:
            price_input = request.form.get(f"price_{sport}")
            if price_input:
                try:
                    prices_dict[sport] = int(price_input)
                except ValueError:
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
            if file and file.filename != "" and allowed_file(file.filename):
                ext = file.filename.rsplit(".", 1)[1].lower()
                new_filename = secure_filename(
                    f"coach_{current_user.id}_{int(datetime.now().timestamp())}.{ext}"
                )
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], new_filename))
                image_filename = new_filename

        if coach is None:
            slug = create_slug(name, sports_str)
            coach = Coach(
                user_id=current_user.id,
                slug=slug,
                name=name,
                sport=sports_str,
                sports_prices=prices_json,
                city=city,
                state=state,
                pincode=pincode,
                price_per_session=starting_price,
                experience_years=exp,
                age=age,
                phone=phone,
                tagline=tagline,
                specialties=specialties,
                profile_image=image_filename,
                achievements=achievements,
                travel_radius=travel_radius,
            )
            db.session.add(coach)
        else:
            coach.name = name
            coach.sport = sports_str
            coach.sports_prices = prices_json
            coach.city = city
            coach.state = state
            coach.pincode = pincode
            coach.price_per_session = starting_price
            coach.experience_years = exp
            coach.age = age
            coach.phone = phone
            coach.tagline = tagline
            coach.specialties = specialties
            coach.profile_image = image_filename
            coach.achievements = achievements
            coach.travel_radius = travel_radius

        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for("coach_dashboard"))

    return render_template("dashboard_coach.html", **context)

# ---------- STRIPE CHECKOUT & WEBHOOK ROUTES ----------

# Create a Checkout Session for a simple one-time purchase (demo)
# Create a Checkout Session using STRIPE PRICE IDS from .env
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

        # Create Checkout Session
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
    """
    Webhook endpoint for Stripe events. Verifies signature and performs idempotent handling.
    Expects STRIPE_WEBHOOK_SECRET in env.
    """
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

    # Idempotency: skip event if already processed
    event_id = event.get("id")
    if StripeEvent.query.filter_by(event_id=event_id).first():
        logger.info(f"Webhook event {event_id} already processed — skipping.")
        return ("Already processed", 200)

    # Save event id early (prevents duplicate processing in concurrent requests)
    try:
        db.session.add(StripeEvent(event_id=event_id))
        db.session.commit()
    except Exception:
        db.session.rollback()
        logger.exception("Could not store StripeEvent; aborting to avoid duplicate work.")
        return ("DB error", 500)

    # Process relevant events
    # Process relevant events
    try:
        if event["type"] == "checkout.session.completed":
            session_obj = event["data"]["object"]
            metadata = session_obj.get("metadata", {})
            
            # CASE A: Subscription Plan (Your existing logic)
            if metadata.get("type") is None: # Or specific check for plans
                client_ref = session_obj.get("client_reference_id")
                customer_id = session_obj.get("customer")
                if client_ref:
                    user = User.query.get(int(client_ref))
                    if user:
                        user.stripe_customer_id = customer_id
                        user.stripe_session_id = session_obj.get("id")
                        # Add logic: user.is_premium = True
                        db.session.commit()

            # CASE B: Coach Booking (New Logic)
            elif metadata.get("type") == "coach_booking":
                booking_id = metadata.get("booking_id")
                if booking_id:
                    booking = Booking.query.get(booking_id)
                    if booking:
                        # 1. Update Status
                        booking.status = "Confirmed"
                        db.session.commit()
                        logger.info(f"Booking {booking_id} confirmed via Stripe.")

                        # 2. Trigger Emails (Move your email logic here)
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
    # Note: We return the 404 status code explicitly
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_server_error(e):
    # It's good practice to have a 500 handler too
    return render_template("404.html"), 500  # You can reuse 404 or make a 500.html

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
