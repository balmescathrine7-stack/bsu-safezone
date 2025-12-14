import os
from time import time
from functools import wraps
from flask import (
    Blueprint, render_template, redirect, url_for, flash,
    session, request, current_app
)
from werkzeug.utils import secure_filename
from .models import (
    db,
    User,
    Report,
    ReportStatus,
    AdminComment,
    StudentReply,
    Notification,
    create_user,
    get_user_by_email,
    verify_password,
    add_report,
    get_all_reports,
    get_user_reports,      
    soft_delete_report,   
    resolve_report,
    mark_as_read,
    update_report_status,
    add_admin_comment,
    add_student_reply,
    add_notification,
    get_user_notifications,
)
from .forms import SignupForm, LoginForm, ReportForm, StudentReplyForm
from . import csrf

views = Blueprint('views', __name__)

ALLOWED_EXTENSIONS = {
    'pdf', 'doc', 'docx', 'txt',
    'jpg', 'jpeg', 'png', 'gif',
    'mp4', 'mov', 'avi', 'mkv', 'webm'
}


# HELPERS
def allowed_file(filename):
    """Check if the uploaded filename has a valid allowed extension."""
    return (
        filename
        and '.' in filename
        and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    )

def save_file(file, email="anonymous"):
    """Save an uploaded file securely inside a user-specific upload folder."""
    if not file or not getattr(file, "filename", None):
        return None
    if not allowed_file(file.filename):
        return None

    filename = secure_filename(file.filename)
    filename = f"{int(time())}_{filename}"

    upload_root = current_app.config.get(
        'UPLOAD_FOLDER',
        os.path.join(current_app.static_folder, "uploads")
    )
    user_folder = os.path.join(upload_root, email)
    os.makedirs(user_folder, exist_ok=True)

    file_path = os.path.join(user_folder, filename)
    try:
        file.save(file_path)
    except Exception:
        return None

    static_folder = current_app.static_folder
    try:
        rel_path = os.path.relpath(file_path, static_folder).replace("\\", "/")
    except Exception:
        rel_path = os.path.join("uploads", email, filename).replace("\\", "/")

    return rel_path

def admin_required(func):
    """Decorator that restricts access to admin-only routes."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user' not in session or session.get('role') != "admin":
            flash("Admin access only", "error")
            return redirect(url_for('views.admin_login'))
        return func(*args, **kwargs)
    return wrapper


# ROUTES
@views.route('/')
def home():
    """Redirect users to the login page."""
    return redirect(url_for('views.login'))

def is_batstateu_email(email):
    """Validate that the email belongs to BatStateU domain."""
    return email.lower().endswith("@g.batstate-u.edu.ph")

@views.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handle student account registration."""
    form = SignupForm()

    if form.validate_on_submit():
        email = form.email.data.lower()

        if not is_batstateu_email(email):
            flash("Only BatStateU student emails (@g.batstate-u.edu.ph) are allowed.", "error")
            return redirect(url_for('views.signup'))

        if get_user_by_email(email):
            flash("Email already exists", "error")
            return redirect(url_for('views.signup'))

        create_user(
            form.full_name.data,
            email,
            form.password.data
        )

        flash("Account created successfully! Please login.", "success")
        return redirect(url_for('views.login'))

    return render_template("signup.html", form=form)


@views.route('/login', methods=['GET', 'POST'])
def login():
    """Authenticate and log in student users."""
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data.lower()

        if not is_batstateu_email(email):
            flash("Only BatStateU student emails are allowed.", "error")
            return redirect(url_for('views.login'))

        user = get_user_by_email(email)

        if user and verify_password(user, form.password.data) and user.role == "user":
            session['user'] = user.email
            session['role'] = user.role
            flash("Logged in successfully", "success")
            return redirect(url_for('views.student_dashboard'))

        flash("Invalid email or password", "error")

    return render_template("login.html", form=form)

# Login (admin)
@views.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    """Authenticate and log in admin users."""
    form = LoginForm()
    if form.validate_on_submit():
        user = get_user_by_email(form.email.data)
        if user and verify_password(user, form.password.data) and user.role == "admin":
            session['user'] = user.email
            session['role'] = user.role
            flash("Admin logged in successfully", "success")
            return redirect(url_for('views.admin_dashboard'))
        flash("Invalid credentials or not an admin account", "error")
    return render_template("admin_login.html", form=form)


# Logout
@views.route('/logout')
def logout():
    """Clear session and log out the current user."""
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for('views.login'))

@views.route('/admin-logout')
def admin_logout():
    """Log out the currently logged-in admin."""
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for('views.admin_login'))


# Student Dashboard
@views.route('/dashboard', methods=['GET', 'POST'])
def student_dashboard():
    """Display student dashboard and handle report submission."""
    if 'user' not in session or session.get('role') != "user":
        flash("Please login first as student", "error")
        return redirect(url_for('views.login'))

    form = ReportForm()
    reply_form = StudentReplyForm()
    user_email = session['user']
    user = get_user_by_email(user_email)
    if not user:
        flash("User not found", "error")
        session.clear()
        return redirect(url_for('views.login'))

    if form.validate_on_submit() and 'submit' in request.form:
        file_path = None
        if form.file_upload.data:
            file_path = save_file(form.file_upload.data, user_email)
            if not file_path:
                flash("Invalid file type or upload failed!", "error")
                return redirect(url_for('views.student_dashboard'))

        add_report(
            title=form.title.data,
            description=form.description.data,
            email=user_email,
            file_path=file_path,
            anonymous=form.anonymous.data
        )
        flash("Report submitted successfully", "success")
        return redirect(url_for('views.student_dashboard'))

    reports = get_user_reports(user_email)
    notifications = get_user_notifications(user_email)

    report_data = []
    for r in reports:
        report_data.append({
            "id": r.id,
            "title": r.title if not getattr(r, 'anonymous', False) else "Anonymous Report",
            "description": r.description,
            "anonymous": getattr(r, 'anonymous', False),
            "owner_name": "You" if getattr(r, 'anonymous', False) else (r.user.full_name if r.user else "Unknown"),
            "status": r.status_rel.name if r.status_rel else "Pending",
            "file_url": url_for('static', filename=r.file_path) if r.file_path else None,
            "admin_comment": r.admin_comment.comment if r.admin_comment else None,
            "admin_comment_created": r.admin_comment.created_at if r.admin_comment else None,
            "student_replies": r.student_replies,
            "created_at": r.created_at
        })

    return render_template(
        "student_dashboard.html",
        user=user,
        form=form,
        reply_form=reply_form,
        reports=report_data,
        notifications=notifications
    )

# Student reply
@views.route('/reply-comment/<int:report_id>', methods=['POST'])
@csrf.exempt
def reply_comment(report_id):
    """Allow students to reply to admin comments on their reports."""
    if 'user' not in session or session.get('role') != "user":
        flash("Please login first as student", "error")
        return redirect(url_for('views.login'))

    form = StudentReplyForm()
    if form.validate_on_submit():
        user = get_user_by_email(session['user'])
        if not user:
            flash("User not found", "error")
            return redirect(url_for('views.login'))
        success = add_student_reply(report_id, user.id, form.reply.data)
        flash("Reply submitted successfully" if success else "Failed to submit reply",
              "success" if success else "error")
    else:
        flash("Reply cannot be empty", "error")

    return redirect(url_for('views.student_dashboard'))

@views.route('/admin-dashboard', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    """Display admin dashboard and handle notifications."""
    admin = get_user_by_email(session['user'])

    if request.method == "POST":
        message = request.form.get("message")
        target = request.form.get("target")

        if not message or not target:
            flash("Message and target are required", "error")
            return redirect(url_for('views.admin_dashboard'))

        if target == "all":
            students = User.query.filter_by(role="user").all()
            for student in students:
                add_notification(
                    message=message,
                    receiver_email=student.email,
                    sender_email=admin.email
                )
        else:
            add_notification(
                message=message,
                receiver_email=target,
                sender_email=admin.email
            )

        flash("Notification sent successfully", "success")
        return redirect(url_for('views.admin_dashboard'))

    reports = (
        Report.query
        .filter_by(deleted_by_admin=False)
        .order_by(Report.created_at.desc())
        .all()
    )

    total = len(reports)
    resolved = len([r for r in reports if r.status_rel and r.status_rel.name == "Resolved"])
    pending = total - resolved

    students = User.query.filter_by(role="user").all()

    return render_template(
        "admin_dashboard.html",
        admin=admin,
        reports=reports,
        students=students,
        total=total,
        resolved=resolved,
        pending=pending
    )


# Admin Actions
@views.route('/delete-report/<int:report_id>', methods=['POST'])
@csrf.exempt
@admin_required
def delete_report_route(report_id):
    """Soft-delete a report from admin dashboard view."""
    success = soft_delete_report(report_id)
    flash("Report deleted from admin view" if success else "Report not found",
          "success" if success else "error")
    return redirect(url_for('views.admin_dashboard'))

@views.route('/resolve-report/<int:report_id>', methods=['POST'])
@csrf.exempt
@admin_required
def resolve_report_route(report_id):
    """Mark a report as resolved."""
    success = resolve_report(report_id)
    flash("Report resolved" if success else "Failed to resolve", "success" if success else "error")
    return redirect(url_for('views.admin_dashboard'))

@views.route('/mark-read/<int:report_id>', methods=['POST'])
@csrf.exempt
@admin_required
def mark_read_route(report_id):
    """Mark a report as read by admin."""
    success = mark_as_read(report_id)
    flash("Marked as read" if success else "Failed to mark", "success" if success else "error")
    return redirect(url_for('views.admin_dashboard'))

@views.route('/add-comment/<int:report_id>', methods=['POST'])
@csrf.exempt
@admin_required
def add_comment(report_id):
    """Add admin comment and optionally update report status."""
    comment_text = request.form.get("comment")
    status_text = request.form.get("status")
    admin = get_user_by_email(session['user'])
    report = db.session.get(Report, report_id)
    if not report:
        flash("Report not found", "error")
        return redirect(url_for('views.admin_dashboard'))
    if comment_text:
        add_admin_comment(report_id, admin.id, comment_text)
    if status_text:
        update_report_status(report_id, status_text)
    flash("Updated successfully", "success")
    return redirect(url_for('views.admin_dashboard'))

@views.route('/about')
def about():
    """Render the About page."""
    return render_template("about.html")

@views.route('/contact', methods=['GET', 'POST'])
def contact():
    """Handle contact form submissions."""
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        message = request.form.get("message")
        if not all([name, email, message]):
            flash("All fields are required", "error")
            return redirect(url_for('views.contact'))
        flash("Your message has been sent successfully", "success")
        return redirect(url_for('views.contact'))
    return render_template("contact.html")
