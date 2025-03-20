"""
Forms for Stock Tracker Application
Includes authentication forms with validation
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from models import User

class RegistrationForm(FlaskForm):
    """User registration form with validation"""
    username = StringField('Username', 
                          validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('Email',
                       validators=[DataRequired(), Email()])
    password = PasswordField('Password', 
                            validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password',
                                    validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
    
    def validate_username(self, username):
        """Check if username already exists"""
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username is already taken. Please choose a different one.')
    
    def validate_email(self, email):
        """Check if email already exists"""
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email is already registered. Please use a different one.')
    
    def validate_password(self, password):
        """Validate password strength"""
        pwd = password.data
        if len(pwd) < 8:
            raise ValidationError('Password must be at least 8 characters long.')
        
        # Check for at least one uppercase, one lowercase, one digit and one special character
        if not any(c.isupper() for c in pwd):
            raise ValidationError('Password must contain at least one uppercase letter.')
        if not any(c.islower() for c in pwd):
            raise ValidationError('Password must contain at least one lowercase letter.')
        if not any(c.isdigit() for c in pwd):
            raise ValidationError('Password must contain at least one number.')
        if not any(c in '!@#$%^&*()_-+={}[]|:;"\'<>,.?/~`' for c in pwd):
            raise ValidationError('Password must contain at least one special character.')

class LoginForm(FlaskForm):
    """User login form"""
    username = StringField('Username or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class ChangePasswordForm(FlaskForm):
    """Form for changing password"""
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', 
                                validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password',
                                    validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')
    
    def validate_new_password(self, new_password):
        """Validate password strength"""
        pwd = new_password.data
        if len(pwd) < 8:
            raise ValidationError('Password must be at least 8 characters long.')
        
        # Check for at least one uppercase, one lowercase, one digit and one special character
        if not any(c.isupper() for c in pwd):
            raise ValidationError('Password must contain at least one uppercase letter.')
        if not any(c.islower() for c in pwd):
            raise ValidationError('Password must contain at least one lowercase letter.')
        if not any(c.isdigit() for c in pwd):
            raise ValidationError('Password must contain at least one number.')
        if not any(c in '!@#$%^&*()_-+={}[]|:;"\'<>,.?/~`' for c in pwd):
            raise ValidationError('Password must contain at least one special character.')

class ResetPasswordRequestForm(FlaskForm):
    """Form for requesting password reset"""
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    """Form for resetting password"""
    password = PasswordField('New Password', 
                            validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password',
                                    validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')
    
    def validate_password(self, password):
        """Validate password strength"""
        pwd = password.data
        if len(pwd) < 8:
            raise ValidationError('Password must be at least 8 characters long.')
        
        # Check for at least one uppercase, one lowercase, one digit and one special character
        if not any(c.isupper() for c in pwd):
            raise ValidationError('Password must contain at least one uppercase letter.')
        if not any(c.islower() for c in pwd):
            raise ValidationError('Password must contain at least one lowercase letter.')
        if not any(c.isdigit() for c in pwd):
            raise ValidationError('Password must contain at least one number.')
        if not any(c in '!@#$%^&*()_-+={}[]|:;"\'<>,.?/~`' for c in pwd):
            raise ValidationError('Password must contain at least one special character.')

class WatchlistForm(FlaskForm):
    """Form for creating/editing watchlists"""
    name = StringField('Watchlist Name', validators=[DataRequired(), Length(min=1, max=50)])
    submit = SubmitField('Save Watchlist')

class AddStockForm(FlaskForm):
    """Form for adding stocks to watchlist"""
    symbol = StringField('Stock Symbol', validators=[DataRequired(), Length(min=1, max=10)])
    watchlist = SelectField('Watchlist', coerce=int)
    submit = SubmitField('Add Stock')
