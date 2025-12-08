import os

# 1. Get the absolute path of the project folder (D:\game-changer)
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-please-change'
    
    # 2. Replicate the winning path logic
    # We place the DB in the root folder to avoid 'instance' folder issues
    # This produces: sqlite:///D:\game-changer\game_changer.db
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'game_changer.db')
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False