from app import create_app
from app.models import db

def init_db():
    # Create app with development config
    app = create_app('development')
    
    # Push an application context
    with app.app_context():
        # Create all database tables
        db.create_all()
        print("Database initialized successfully!")

if __name__ == '__main__':
    init_db() 