import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# 1. Setup a fresh, isolated Flask app
app = Flask(__name__)

# 2. Force an absolute path that is 100% safe
# We explicitly use os.getcwd() to get D:\game-changer
base_dir = os.getcwd()
db_path = os.path.join(base_dir, "test_database.db")

# 3. Construct the URI manually
# On Windows, we use 3 slashes /// and the direct path
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

print(f"--- DEBUGGING ---")
print(f"Base Directory: {base_dir}")
print(f"Target Database: {db_path}")
print(f"Target URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
print(f"-----------------")

db = SQLAlchemy(app)

class TestModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)

# 4. Try to create the DB
try:
    with app.app_context():
        db.create_all()
        print("\n✅ SUCCESS! The database 'test_database.db' was created.")
        print("This proves Flask-SQLAlchemy works on your machine.")
        print("The issue is likely inside your original 'app.py' or 'config.py'.")
except Exception as e:
    print(f"\n❌ FAILED. Error details below:")
    print(e)