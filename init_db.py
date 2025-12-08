import os
import sys
import sqlite3
from pathlib import Path

print("--- 1. FILE SYSTEM CHECK ---")
# Get the absolute path to the current folder
base_dir = Path(__file__).parent.absolute()
instance_dir = base_dir / "instance"
db_path = instance_dir / "game_changer.db"

print(f"Base Directory: {base_dir}")
print(f"Instance Dir:   {instance_dir}")
print(f"Target DB:      {db_path}")

# Check if we can create the folder and write a dummy file
try:
    instance_dir.mkdir(exist_ok=True)
    print("✅ 'instance' folder exists/created.")
    
    # Try writing a test file to prove we have permission
    test_file = instance_dir / "permission_test.txt"
    test_file.write_text("testing write access")
    print("✅ Write permission confirmed (test file created).")
    test_file.unlink() # Delete the test file
    print("✅ Test file cleaned up.")
except Exception as e:
    print(f"❌ CRITICAL ERROR: File system permission denied. {e}")
    sys.exit(1)

print("\n--- 2. RAW SQLITE CHECK ---")
# Try creating the DB without Flask/SQLAlchemy to see if Windows locks it
try:
    # Convert path to string
    str_db_path = str(db_path)
    conn = sqlite3.connect(str_db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS test_table (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()
    print("✅ Raw SQLite connection successful. The file path is valid.")
except Exception as e:
    print(f"❌ SQLITE ERROR: {e}")
    print("This means the issue is strictly how the path is formatted for the DB driver.")
    sys.exit(1)

print("\n--- 3. FLASK-SQLALCHEMY CHECK ---")
try:
    from app import app, db
    
    # We construct the URI manually using the verified path.
    # On Windows, we need 3 slashes followed by the absolute path.
    # We also force forward slashes to avoid escaping issues.
    clean_path = str(db_path).replace("\\", "/")
    uri = f"sqlite:////{clean_path}"
    
    print(f"Configuring Flask with URI: {uri}")
    app.config['SQLALCHEMY_DATABASE_URI'] = uri
    
    with app.app_context():
        db.create_all()
        print("✅ SUCCESS: Flask tables created via SQLAlchemy!")
        
except Exception as e:
    print(f"❌ FLASK ERROR: {e}")