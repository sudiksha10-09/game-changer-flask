from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
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
from werkzeug.security import generate_password_hash, check_password_hash
from slugify import slugify
import os

# ----------------- APP SETUP -----------------

app = Flask(__name__)
app.config.from_object("config.Config")

# make sure instance folder exists
os.makedirs(os.path.dirname(app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", "")), exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ----------------- MODELS -----------------


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20), default="coach")  # 'coach' or 'academy'
    name = db.Column(db.String(120), nullable=False)
    city = db.Column(db.String(120), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    coach_profile = db.relationship("Coach", backref="user", uselist=False)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Coach(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    slug = db.Column(db.String(150), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    sport = db.Column(db.String(80), nullable=False)
    city = db.Column(db.String(120), nullable=False)

    price_per_session = db.Column(db.Integer, nullable=False)
    experience_years = db.Column(db.Integer, default=0)
    rating = db.Column(db.Float, default=4.5)
    tagline = db.Column(db.String(255), nullable=True)
    specialties = db.Column(db.Text, nullable=True)  # comma-separated


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Availability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey("coach.id"), nullable=False)
    days = db.Column(db.String(120))                # "Mon,Tue,Fri"
    time_from = db.Column(db.String(20))            # "06:00"
    time_to = db.Column(db.String(20))              # "10:00"
    coach = db.relationship("Coach", backref="availability", lazy=True)


class BookingRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey("coach.id"), nullable=False)
    name = db.Column(db.String(120))
    email = db.Column(db.String(120))
    preferred_date = db.Column(db.String(25))
    preferred_time = db.Column(db.String(25))
    message = db.Column(db.Text)
    coach = db.relationship("Coach", backref="bookings", lazy=True)

# ----------------- UTILS -----------------


def create_coach_slug(name: str, sport: str) -> str:
    base = slugify(f"{name}-{sport}")
    slug = base
    counter = 2
    while Coach.query.filter_by(slug=slug).first():
        slug = f"{base}-{counter}"
        counter += 1
    return slug


def seed_sample_data():
    """Create tables & some sample coaches if DB empty."""
    db.create_all()

    if User.query.first():
        return  # already seeded

    # sample users
    u1 = User(role="coach", name="Arjun Mehta", city="Mumbai", email="arjun@example.com")
    u1.set_password("password123")
    u2 = User(role="coach", name="Riya Kulkarni", city="Pune", email="riya@example.com")
    u2.set_password("password123")
    u3 = User(role="coach", name="Akash Singh", city="Bengaluru", email="akash@example.com")
    u3.set_password("password123")

    db.session.add_all([u1, u2, u3])
    db.session.flush()  # so they get IDs

    c1 = Coach(
        user_id=u1.id,
        slug=create_coach_slug("Arjun Mehta", "Cricket"),
        name="Arjun Mehta",
        sport="Cricket",
        city="Mumbai",
        price_per_session=1200,
        experience_years=6,
        rating=4.7,
        tagline="Ex-U19 Mumbai player, batting technique & temperament.",
        specialties="Batting fundamentals, Power-hitting, Shot selection, Match scenarios",
    )

    c2 = Coach(
        user_id=u2.id,
        slug=create_coach_slug("Riya Kulkarni", "Football"),
        name="Riya Kulkarni",
        sport="Football",
        city="Pune",
        price_per_session=900,
        experience_years=4,
        rating=4.6,
        tagline="AFC-C certified, grassroots & youth development.",
        specialties="Ball control, Passing drills, Speed & agility, Strength & conditioning",
    )

    c3 = Coach(
        user_id=u3.id,
        slug=create_coach_slug("Akash Singh", "Strength & Conditioning"),
        name="Akash Singh",
        sport="Strength & Conditioning",
        city="Bengaluru",
        price_per_session=1500,
        experience_years=8,
        rating=4.8,
        tagline="Certified S&C coach working with state-level athletes.",
        specialties="Strength building, Injury rehab, Endurance, Flexibility",
    )

    db.session.add_all([c1, c2, c3])
    db.session.commit()
    print("Seeded sample data.")


# ----------------- ROUTES: PUBLIC PAGES -----------------


@app.route("/")
def home():
    featured_coaches = Coach.query.order_by(Coach.rating.desc()).limit(3).all()
    return render_template("home.html", coaches=featured_coaches)


@app.route("/coaches")
def coaches():
    sport = request.args.get("sport", "", type=str)
    city = request.args.get("city", "", type=str)
    min_price = request.args.get("min_price", type=int)
    max_price = request.args.get("max_price", type=int)
    min_exp = request.args.get("min_exp", type=int)
    min_rating = request.args.get("min_rating", type=float)

    query = Coach.query

    if sport:
        query = query.filter(Coach.sport.ilike(f"%{sport}%"))
    if city:
        query = query.filter(Coach.city.ilike(f"%{city}%"))
    if min_price is not None:
        query = query.filter(Coach.price_per_session >= min_price)
    if max_price is not None:
        query = query.filter(Coach.price_per_session <= max_price)
    if min_exp is not None:
        query = query.filter(Coach.experience_years >= min_exp)
    if min_rating is not None:
        query = query.filter(Coach.rating >= min_rating)

    sort = request.args.get("sort", "relevance")
    if sort == "price_asc":
        query = query.order_by(Coach.price_per_session.asc())
    elif sort == "price_desc":
        query = query.order_by(Coach.price_per_session.desc())
    elif sort == "experience_desc":
        query = query.order_by(Coach.experience_years.desc())
    elif sort == "rating_desc":
        query = query.order_by(Coach.rating.desc())
    else:
        query = query.order_by(Coach.id.desc())

    coaches_list = query.all()

    return render_template(
        "coaches.html",
        coaches=coaches_list,
        sport=sport,
        city=city,
        min_price=min_price or "",
        max_price=max_price or "",
        min_exp=min_exp or "",
        min_rating=min_rating or "",
        sort=sort,
    )


@app.route("/coaches/<slug>")
def coach_detail(slug):
    coach = Coach.query.filter_by(slug=slug).first_or_404()
    specialties = [s.strip() for s in (coach.specialties or "").split(",") if s.strip()]
    return render_template("coach_detail.html", coach=coach, specialties=specialties)


# ----------------- AUTH -----------------


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        city = request.form.get("city", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "coach")

        if not name or not email or not password:
            flash("Please fill all required fields.", "danger")
        elif User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
        else:
            user = User(name=name, city=city, email=email, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash("Account created. Welcome to Game Changer!", "success")
            if role == "coach":
                return redirect(url_for("coach_dashboard"))
            else:
                return redirect(url_for("home"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Logged in successfully.", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("home"))
        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


# ----------------- COACH DASHBOARD -----------------


@app.route("/dashboard/coach", methods=["GET", "POST"])
@login_required
def coach_dashboard():
    if current_user.role != "coach":
        flash("Only coaches can access this page.", "danger")
        return redirect(url_for("home"))

    coach = current_user.coach_profile

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        sport = request.form.get("sport", "").strip()
        city = request.form.get("city", "").strip()
        price = request.form.get("price_per_session", type=int)
        exp = request.form.get("experience_years", type=int)
        tagline = request.form.get("tagline", "").strip()
        specialties = request.form.get("specialties", "").strip()

        if not all([name, sport, city, price]):
            flash("Please fill all required fields.", "danger")
        else:
            if coach is None:
                slug = create_coach_slug(name, sport)
                coach = Coach(
                    user_id=current_user.id,
                    slug=slug,
                    name=name,
                    sport=sport,
                    city=city,
                    price_per_session=price,
                    experience_years=exp or 0,
                    tagline=tagline,
                    specialties=specialties,
                )
                db.session.add(coach)
            else:
                coach.name = name
                coach.sport = sport
                coach.city = city
                coach.price_per_session = price
                coach.experience_years = exp or 0
                coach.tagline = tagline
                coach.specialties = specialties

            db.session.commit()
            flash("Profile saved to Game Changer.", "success")
            return redirect(url_for("coach_dashboard"))

    return render_template("dashboard_coach.html", coach=coach)

# ----------------- AVAILABILITY & BOOKING -----------------

@app.route("/dashboard/coach/availability", methods=["POST"])
@login_required
def save_availability():
    if current_user.role != "coach":
        flash("Only coaches can update availability.", "danger")
        return redirect(url_for("home"))

    coach = current_user.coach_profile
    days = ",".join(request.form.getlist("days"))
    time_from = request.form.get("time_from")
    time_to = request.form.get("time_to")

    # create or update
    if coach.availability:
        coach.availability[0].days = days
        coach.availability[0].time_from = time_from
        coach.availability[0].time_to = time_to
    else:
        avail = Availability(coach_id=coach.id, days=days, time_from=time_from, time_to=time_to)
        db.session.add(avail)

    db.session.commit()
    flash("Availability saved.", "success")
    return redirect(url_for("coach_dashboard"))


@app.route("/book/<int:coach_id>", methods=["POST"])
def book_session(coach_id):
    coach = Coach.query.get_or_404(coach_id)

    booking = BookingRequest(
        coach_id=coach_id,
        name=request.form.get("name"),
        email=request.form.get("email"),
        preferred_date=request.form.get("preferred_date"),
        preferred_time=request.form.get("preferred_time"),
        message=request.form.get("message"),
    )
    db.session.add(booking)
    db.session.commit()

    flash("Request sent! Coach will contact you soon.", "success")
    return redirect(url_for("coach_detail", slug=coach.slug))

# ----------------- MAIN -----------------

if __name__ == "__main__":
    with app.app_context():
        seed_sample_data()
    app.run(debug=True)
