# scripts/add_stripe_columns.py
import os
from sqlalchemy import create_engine, text

db_url = os.getenv("DATABASE_URL")
if db_url is None:
    raise SystemExit("DATABASE_URL not set in environment. Export it first.")

# Normalize postgres:// → postgresql:// for SQLAlchemy
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

engine = create_engine(db_url)

with engine.connect() as conn:
    print("Connected to:", engine.dialect.name)
    try:
        conn.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR'))
        conn.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS stripe_session_id VARCHAR'))
        print("✔ Columns added (or already exist).")
    except Exception as e:
        print("ERROR:", e)
