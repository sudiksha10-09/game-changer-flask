import os
from app import app, db

# 1. Use the EXACT path logic that worked in debug_flask.py
# We calculate the absolute path to D:\game-changer\game_changer.db
base_dir = os.getcwd()
db_path = os.path.join(base_dir, "game_changer.db").replace("\\", "/")

# 2. Force the app to use this working path
# We use 3 slashes (sqlite:///) + the absolute path
uri = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_DATABASE_URI'] = uri

print(f"--- APPLYING FIX ---")
print(f"Target Database: {db_path}")
print(f"Force Config URI: {uri}")

# 3. Create the tables
with app.app_context():
    try:
        db.create_all()
        print("\n✅ SUCCESS: Real application database created!")
        print("You should see 'game_changer.db' in your project folder now.")
    except Exception as e:
        print("\n❌ ERROR:")
        print(e)