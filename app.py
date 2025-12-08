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

# ---------------------------------
# APP CONFIG
# ---------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key-change-this"

# ---- EMAIL CONFIGURATION (GMAIL) ----
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'sudiksha746@gmail.com' 
app.config['MAIL_PASSWORD'] = 'gers mqwk igte lwch'
app.config['MAIL_DEFAULT_SENDER'] = 'sudiksha746@gmail.com'

mail = Mail(app)

# ---- DB Configuration ----
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "instance", "game_changer.db")
os.makedirs(os.path.join(BASE_DIR, "instance"), exist_ok=True)

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ---- File Upload Configuration ----
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

SPORTS_LIST = [
    "Cricket", "Football", "Badminton", "Kabaddi", "Hockey", "Athletics", 
    "Swimming", "Tennis", "Table Tennis", "Basketball", "Volleyball", 
    "Wrestling", "Boxing", "Shooting", "Archery", "Weightlifting", 
    "Gymnastics", "Judo", "Squash", "Chess"
]

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------------------------------
# MODELS
# ---------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20), default="hirer") # 'coach' or 'hirer'
    is_organization = db.Column(db.Boolean, default=False) # <--- NEW STRATEGY FIELD
    name = db.Column(db.String(120), nullable=False)
    city = db.Column(db.String(120))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    
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
    profile_image = db.Column(db.String(300), default='default_coach.jpg')
    achievements = db.Column(db.Text)
    is_verified = db.Column(db.Boolean, default=False)
    
    # Relationships
    bookings_received = db.relationship("Booking", backref="coach", lazy=True)

    def get_sports_list(self):
        return self.sport.split(',') if self.sport else []
    
    def get_price_dict(self):
        try:
            return json.loads(self.sports_prices) if self.sports_prices else {}
        except:
            return {}

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('coach.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # The Hirer
    sport = db.Column(db.String(100), nullable=False)
    booking_date = db.Column(db.Date, nullable=False)
    booking_time = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='Pending') 
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_slug(name, sport_str):
    first_sport = sport_str.split(',')[0] if sport_str else "coach"
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
@app.route("/")
def home():
    top_coaches = Coach.query.order_by(Coach.rating.desc()).limit(3).all()
    return render_template("home.html", coaches=top_coaches)

@app.route("/plans")
def plans():
    return render_template("plans.html")

@app.route("/coaches")
def coaches():
    sport_filter = request.args.get("sport", "").strip()
    city_filter = request.args.get("city", "").strip()
    query = Coach.query
    if sport_filter:
        query = query.filter(Coach.sport.ilike(f"%{sport_filter}%"))
    if city_filter:
        query = query.filter(Coach.city.ilike(f"%{city_filter}%"))
    coaches_list = query.order_by(Coach.id.desc()).all()
    return render_template("coaches.html", coaches=coaches_list)

@app.route("/coaches/<slug>")
def coach_detail(slug):
    coach = Coach.query.filter_by(slug=slug).first_or_404()
    achievements = coach.achievements.splitlines() if coach.achievements else []
    specialties = [s.strip() for s in (coach.specialties or "").split(",") if s.strip()]
    return render_template("coach_detail.html", coach=coach, achievements=achievements, specialties=specialties)

@app.route("/book/<int:coach_id>", methods=["POST"])
@login_required
def book_session(coach_id):
    coach = Coach.query.get_or_404(coach_id)
    
    # Basic Plan Limitation Logic (Example)
    # If !current_user.is_organization and len(my_bookings) > 3:
    #    flash("Free limit reached. Upgrade to Recruiter Pro.", "warning")
    #    return redirect(url_for('plans'))

    sport = request.form.get("sport")
    date_str = request.form.get("date")
    time_slot = request.form.get("time")
    message = request.form.get("message")
    
    if not date_str or not time_slot:
        flash("Please select a valid date and time.", "danger")
        return redirect(url_for('coach_detail', slug=coach.slug))
        
    try:
        date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        flash("Invalid date format.", "danger")
        return redirect(url_for('coach_detail', slug=coach.slug))
        
    new_booking = Booking(
        coach_id=coach.id,
        user_id=current_user.id,
        sport=sport,
        booking_date=date_obj,
        booking_time=time_slot,
        message=message,
        status="Confirmed" 
    )
    
    db.session.add(new_booking)
    db.session.commit()
    
    flash(f"Session booked successfully with Coach {coach.name}!", "success")
    return redirect(url_for('coach_dashboard'))

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("coach_dashboard"))
        
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "hirer") # Default to 'hirer' (Student/Recruiter)
        org_type = request.form.get("org_type", "individual") # 'individual' or 'organization'
        
        # Logic: If they are a hirer and selected 'organization', set flag True
        is_org = False
        if role == 'hirer' and org_type == 'organization':
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
            
            if role == 'coach':
                return redirect(url_for("coach_dashboard"))
            else:
                # Redirect Hirers to Plans page first to upsell, or Dashboard
                if is_org:
                    return redirect(url_for("plans")) # Send organizations to pricing immediately
                return redirect(url_for("home")) 
                
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("coach_dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            if user.role == 'coach':
                return redirect(url_for("coach_dashboard"))
            else:
                return redirect(url_for("home"))
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
        otp = ''.join(random.choices(string.digits, k=6))
        session['verification_otp'] = otp
        msg = Message("Verify your Game Changer Account", recipients=[current_user.email])
        msg.body = f"Hello {current_user.name},\n\nYour Verification OTP is: {otp}\n\nDo not share this with anyone."
        mail.send(msg)
        return {"status": "success", "message": "OTP sent to " + current_user.email}
    except Exception as e:
        print(e)
        return {"status": "error", "message": "Failed to send email. Check app config."}

@app.route("/verify/coach", methods=["POST"])
@login_required
def verify_coach():
    user_code = request.form.get("code")
    stored_otp = session.get('verification_otp')
    if stored_otp and user_code == stored_otp:
        if current_user.coach_profile:
            current_user.coach_profile.is_verified = True
            db.session.commit()
            session.pop('verification_otp', None)
            flash("Success! You are now a Verified Coach.", "success")
        else:
            flash("Please create a coach profile first.", "warning")
    else:
        flash("Invalid OTP. Please try again.", "danger")
    return redirect(url_for("coach_dashboard"))

@app.route("/dashboard", methods=["GET", "POST"]) # Universal Dashboard Link
@login_required
def coach_dashboard():
    # If user is a coach, show coach profile management
    coach = current_user.coach_profile
    
    my_bookings = Booking.query.filter_by(user_id=current_user.id).order_by(Booking.booking_date.desc()).all()
    
    received_bookings = []
    if coach:
        received_bookings = Booking.query.filter_by(coach_id=coach.id).order_by(Booking.booking_date.desc()).all()
        
    context = {
        "coach": coach, 
        "sports_list": SPORTS_LIST,
        "my_bookings": my_bookings,
        "received_bookings": received_bookings
    }

    if request.method == "POST":
        if current_user.role != 'coach':
             flash("Only coaches can update profile settings.", "danger")
             return redirect(url_for('coach_dashboard'))

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

        try:
            exp = int(exp_raw) if exp_raw else 0
            age = int(age_raw) if age_raw else 0
        except ValueError:
            flash("Age/Experience must be numbers.", "danger")
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

        image_filename = coach.profile_image if coach else 'default_coach.jpg'
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file and file.filename != '' and allowed_file(file.filename):
                ext = file.filename.rsplit('.', 1)[1].lower()
                new_filename = secure_filename(f"coach_{current_user.id}_{int(datetime.now().timestamp())}.{ext}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
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

        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for("coach_dashboard"))

    return render_template("dashboard_coach.html", **context)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)