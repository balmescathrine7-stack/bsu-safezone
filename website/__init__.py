import os
from time import time
from flask import Flask, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash

# Initialize database ORM
db = SQLAlchemy()

# Enable CSRF protection
csrf = CSRFProtect()

# Define allowed file extensions for uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi', 'mkv', 'webm'}


# Application configuration settings
class Config:
    SECRET_KEY = "bsuSafezone123"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200 MB


# Check if the uploaded file has a valid extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Save uploaded file securely inside the user's folder
def save_file(file, email="anonymous"):
    if not file or not allowed_file(file.filename):
        return None

    filename = secure_filename(file.filename)
    filename = f"{int(time())}_{filename}"

    user_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], email)
    os.makedirs(user_folder, exist_ok=True)

    file_path = os.path.join(user_folder, filename)
    try:
        file.save(file_path)
    except Exception as e:
        print(f"Failed to save file: {e}")
        return None

    return os.path.join('uploads', email, filename).replace("\\", "/")


# Create a default admin account if it does not exist
def create_admin():
    from .models import User

    admin_email = "safezone@g.batstate-u.edu.ph"
    admin_password = "safezone123"

    admin = User.query.filter_by(email=admin_email).first()

    if not admin:
        hashed = generate_password_hash(admin_password)
        new_admin = User(
            full_name="Admin",
            email=admin_email,
            password=hashed,
            role="admin"
        )
        db.session.add(new_admin)
        db.session.commit()
        print("Admin created.")
    else:
        if admin.role != "admin":
            admin.role = "admin"
            db.session.commit()
        print("Admin already exists.")


# Application factory function that creates and configures the Flask app
def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    basedir = os.path.abspath(os.path.dirname(__file__))

    # Configure database storage location
    db_folder = os.path.join(basedir, "database")
    os.makedirs(db_folder, exist_ok=True)
    db_path = os.path.join(db_folder, "bsuDatabase.db")
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"

    # Configure upload directory
    upload_folder = os.path.join(basedir, "static", "uploads")
    os.makedirs(upload_folder, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = upload_folder

    # Initialize Flask extensions
    db.init_app(app)
    csrf.init_app(app)

    # Register application routes
    from .views import views
    app.register_blueprint(views)

    # Initialize database and create default admin account
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not os.environ.get("WERKZEUG_RUN_MAIN"):
        with app.app_context():
            db.create_all()
            create_admin()
            print("Database ready.")

    return app
