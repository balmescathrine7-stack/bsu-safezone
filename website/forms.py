from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, BooleanField, SubmitField, FileField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp
from flask_wtf.file import FileAllowed


# Handles student account registration
class SignupForm(FlaskForm):
    full_name = StringField(
        "Full Name",
        validators=[DataRequired(), Length(min=2, max=120)]
    )
    email = StringField(
        "Email",
        validators=[
            DataRequired(),
            Email(),
            Regexp(
                r'.+@g\.batstate-u\.edu\.ph$',
                message="Use your BatStateU email (@g.batstate-u.edu.ph)"
            ),
            Length(max=120)
        ]
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=6)]
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo('password')]
    )
    submit = SubmitField("Sign Up")


# Handles student login authentication
class LoginForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[
            DataRequired(),
            Email(),
            Regexp(
                r'.+@g\.batstate-u\.edu\.ph$',
                message="Only BatStateU student emails are allowed"
            ),
            Length(max=120)
        ]
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired()]
    )
    submit = SubmitField("Login")


# Handles incident report submission
class ReportForm(FlaskForm):
    title = StringField(
        "Report Title",
        validators=[DataRequired(), Length(max=150)]
    )
    description = TextAreaField(
        "Description",
        validators=[DataRequired()]
    )
    file_upload = FileField(
        "Attach File",
        validators=[
            FileAllowed(
                ['pdf', 'doc', 'docx', 'txt', 'jpg', 'jpeg', 'png', 'gif', 'mp4', 'mov', 'avi', 'mkv'],
                "Invalid file type!"
            )
        ]
    )
    anonymous = BooleanField("Submit Anonymously")
    submit = SubmitField("Submit Report")


# Allows students to reply to admin feedback
class StudentReplyForm(FlaskForm):
    reply = TextAreaField(
        "Your Reply",
        validators=[DataRequired(), Length(min=1)]
    )
    submit = SubmitField("Submit Reply")


# Allows admins to comment and update report status
class AdminCommentForm(FlaskForm):
    comment = TextAreaField(
        "Admin Comment",
        validators=[DataRequired(), Length(min=1)]
    )
    status = SelectField(
        "Update Status",
        choices=[("Pending", "Pending"), ("Read", "Read"), ("Resolved", "Resolved")]
    )
    submit = SubmitField("Update")
