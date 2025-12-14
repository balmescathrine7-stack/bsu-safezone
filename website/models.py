from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


# Represents system users (students and admins)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")

    reports = db.relationship(
        "Report",
        foreign_keys="Report.user_id",
        backref="user",
        lazy=True,
        cascade="all, delete-orphan"
    )

    anonymous_reports = db.relationship(
        "Report",
        foreign_keys="Report.anonymous_owner_id",
        backref="anonymous_user",
        lazy=True,
        cascade="all, delete-orphan"
    )

    admin_comments = db.relationship(
        "AdminComment",
        backref="admin",
        lazy=True,
        cascade="all, delete-orphan"
    )

    student_replies = db.relationship(
        "StudentReply",
        back_populates="user",
        lazy=True,
        cascade="all, delete-orphan"
    )

    notifications_sent = db.relationship(
        "Notification",
        foreign_keys="Notification.sender_id",
        backref="sender",
        lazy=True,
        cascade="all, delete-orphan"
    )

    notifications_received = db.relationship(
        "Notification",
        foreign_keys="Notification.user_id",
        backref="receiver",
        lazy=True,
        cascade="all, delete-orphan"
    )

    # Hash and store user password
    def set_password(self, password):
        self.password = generate_password_hash(password)

    # Verify user password
    def check_password(self, password):
        return check_password_hash(self.password, password)


# Stores possible report statuses (Pending, Read, Resolved)
class ReportStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    reports = db.relationship("Report", backref="status_rel", lazy=True)


# Represents incident reports submitted by students
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    file_path = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    anonymous_owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    status_id = db.Column(db.Integer, db.ForeignKey("report_status.id"), nullable=False)

    deleted_by_admin = db.Column(db.Boolean, default=False)

    admin_comment = db.relationship(
        "AdminComment",
        backref="report",
        uselist=False,
        lazy=True,
        cascade="all, delete-orphan"
    )

    student_replies = db.relationship(
        "StudentReply",
        backref="report",
        lazy=True,
        cascade="all, delete-orphan"
    )


# Stores comments made by admins on reports
class AdminComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey("report.id"), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Stores replies made by students to admin comments
class StudentReply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey("report.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    anonymous = db.Column(db.Boolean, default=False, nullable=False)
    reply = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship(
        "User",
        back_populates="student_replies"
    )


# Stores system notifications for users
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)


# Create a new user account
def create_user(full_name, email, password, role="user"):
    user = User(
        full_name=full_name,
        email=email,
        password=generate_password_hash(password),
        role=role
    )
    db.session.add(user)
    db.session.commit()
    return user


# Retrieve a user by email
def get_user_by_email(email):
    return User.query.filter_by(email=email).first()


# Verify a user's password
def verify_password(user, password):
    return check_password_hash(user.password, password)


# Get or create the default "Pending" report status
def get_default_status():
    status = ReportStatus.query.filter_by(name="Pending").first()
    if not status:
        status = ReportStatus(name="Pending")
        db.session.add(status)
        db.session.commit()
    return status


# Add a new report to the database
def add_report(title, description, email=None, file_path=None, anonymous=False):
    user_id = anon_owner_id = None

    if email:
        user = get_user_by_email(email)
        if not user:
            return False
        if anonymous:
            anon_owner_id = user.id
        else:
            user_id = user.id

    report = Report(
        title=title,
        description=description,
        user_id=user_id,
        anonymous_owner_id=anon_owner_id,
        file_path=file_path,
        status_id=get_default_status().id
    )

    db.session.add(report)
    db.session.commit()
    return True


# Get all reports belonging to a specific user
def get_user_reports(email):
    user = get_user_by_email(email)
    if not user:
        return []

    reports = Report.query.filter(
        (Report.user_id == user.id) | (Report.anonymous_owner_id == user.id)
    ).order_by(Report.created_at.desc()).all()

    for r in reports:
        r.anonymous = r.user_id is None and r.anonymous_owner_id == user.id

    return reports


# Retrieve all reports in the system
def get_all_reports():
    return Report.query.order_by(Report.created_at.desc()).all()


# Soft-delete a report (admin only)
def soft_delete_report(report_id):
    report = db.session.get(Report, report_id)
    if not report:
        return False
    report.deleted_by_admin = True
    db.session.commit()
    return True


# Update the status of a report
def update_report_status(report_id, status_name):
    report = db.session.get(Report, report_id)
    if not report:
        return False

    status = ReportStatus.query.filter_by(name=status_name).first()
    if not status:
        status = ReportStatus(name=status_name)
        db.session.add(status)
        db.session.commit()

    report.status_id = status.id
    db.session.commit()
    return True


# Mark a report as resolved
def resolve_report(report_id):
    return update_report_status(report_id, "Resolved")


# Mark a report as read
def mark_as_read(report_id):
    return update_report_status(report_id, "Read")


# Add or update an admin comment on a report
def add_admin_comment(report_id, admin_id, comment_text):
    report = db.session.get(Report, report_id)
    if not report:
        return False

    if report.admin_comment:
        report.admin_comment.comment = comment_text
        report.admin_comment.admin_id = admin_id
        report.admin_comment.created_at = datetime.utcnow()
    else:
        db.session.add(
            AdminComment(
                report_id=report_id,
                admin_id=admin_id,
                comment=comment_text
            )
        )

    db.session.commit()
    return True


# Add a student reply to a report
def add_student_reply(report_id, user_id, reply_text):
    report = db.session.get(Report, report_id)
    if not report:
        return False

    is_anonymous = report.user_id is None and report.anonymous_owner_id == user_id

    reply = StudentReply(
        report_id=report_id,
        user_id=None if is_anonymous else user_id,
        anonymous=is_anonymous,
        reply=reply_text
    )

    db.session.add(reply)
    db.session.commit()
    return True


# Create a notification for a user
def add_notification(message, receiver_email=None, sender_email=None):
    receiver = get_user_by_email(receiver_email) if receiver_email else None
    sender = get_user_by_email(sender_email) if sender_email else None

    if receiver_email and not receiver:
        return False

    notification = Notification(
        message=message,
        user_id=receiver.id if receiver else None,
        sender_id=sender.id if sender else None
    )

    db.session.add(notification)
    db.session.commit()
    return True


# Retrieve notifications for a specific user
def get_user_notifications(email):
    user = get_user_by_email(email)
    if not user:
        return []

    return Notification.query.filter_by(
        user_id=user.id
    ).order_by(Notification.created_at.desc()).all()
