"""
Authentication routes and functionality for Stock Tracker Application
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_user, current_user, logout_user, login_required
from models import User, LoginLog, AuditLog, db
from forms import LoginForm, RegistrationForm, ChangePasswordForm, ResetPasswordRequestForm, ResetPasswordForm
import datetime
import secrets
import hashlib
from functools import wraps
import re

# Create blueprint
auth = Blueprint('auth', __name__)

# Security constants
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 15  # minutes

def admin_required(f):
    """Decorator for routes that require admin access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

def log_login_attempt(user_id, success=False):
    """Log login attempts for security monitoring"""
    log = LoginLog(
        user_id=user_id,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        success=success
    )
    db.session.add(log)
    db.session.commit()

def log_audit(action, resource_type=None, resource_id=None, details=None):
    """Log user actions for audit trail"""
    user_id = current_user.id if current_user.is_authenticated else None
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=request.remote_addr,
        details=details
    )
    db.session.add(log)
    db.session.commit()

def is_account_locked(user):
    """Check if account is locked due to too many failed login attempts"""
    if user.login_attempts >= MAX_LOGIN_ATTEMPTS:
        # Check if last login attempt was within lockout period
        recent_failed_login = LoginLog.query.filter_by(
            user_id=user.id, 
            success=False
        ).order_by(LoginLog.timestamp.desc()).first()
        
        if recent_failed_login:
            lockout_until = recent_failed_login.timestamp + datetime.timedelta(minutes=LOCKOUT_TIME)
            if datetime.datetime.utcnow() < lockout_until:
                return True
            else:
                # Reset login attempts after lockout period
                user.reset_login_attempts()
        return False
    return False

def validate_password_strength(password):
    """Validate password meets security requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*()_\-+={}[\]|:;"\'<>,.?/~`]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password meets requirements"

@auth.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route"""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Additional server-side validation
        is_valid, message = validate_password_strength(form.password.data)
        if not is_valid:
            flash(message, 'danger')
            return render_template('register.html', title='Register', form=form)
        
        # Create new user
        user = User(
            username=form.username.data,
            email=form.email.data,
            role='user'
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        log_audit('user_registered', 'user', str(user.id), f"New user registered: {user.username}")
        
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html', title='Register', form=form)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    """User login route"""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        # Check if username or email
        if '@' in form.username.data:
            user = User.query.filter_by(email=form.username.data).first()
        else:
            user = User.query.filter_by(username=form.username.data).first()
        
        # If user exists and password is correct
        if user and not is_account_locked(user) and user.check_password(form.password.data):
            # Reset login attempts
            user.reset_login_attempts()
            
            # Update last login time
            user.update_last_login()
            
            # Log successful login
            log_login_attempt(user.id, success=True)
            log_audit('user_login', 'user', str(user.id), "User logged in successfully")
            
            # Set session security
            session.permanent = True
            current_app.permanent_session_lifetime = datetime.timedelta(hours=1)
            
            # Set CSRF token
            session['csrf_token'] = secrets.token_hex(16)
            
            # Login user
            login_user(user, remember=form.remember.data)
            
            # Redirect to next page or home
            next_page = request.args.get('next')
            if next_page and not next_page.startswith('/'):
                # Prevent open redirect vulnerability
                next_page = None
                
            return redirect(next_page or url_for('main.index'))
        else:
            # Handle failed login
            if user:
                if is_account_locked(user):
                    flash('Account is temporarily locked due to too many failed login attempts. Please try again later.', 'danger')
                else:
                    user.increment_login_attempts()
                    log_login_attempt(user.id, success=False)
                    
                    attempts_left = MAX_LOGIN_ATTEMPTS - user.login_attempts
                    if attempts_left > 0:
                        flash(f'Login failed. You have {attempts_left} attempts remaining before your account is locked.', 'danger')
                    else:
                        flash('Your account has been temporarily locked due to too many failed login attempts.', 'danger')
            else:
                # Don't reveal if username exists or not (security best practice)
                flash('Login failed. Please check your username and password.', 'danger')
                
            # Add a small delay to prevent brute force attacks
            import time
            time.sleep(1)
    
    return render_template('login.html', title='Login', form=form)

@auth.route('/logout')
def logout():
    """User logout route"""
    if current_user.is_authenticated:
        log_audit('user_logout', 'user', str(current_user.id), "User logged out")
    
    logout_user()
    
    # Clear session data
    session.clear()
    
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))

@auth.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change password route"""
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.current_password.data):
            # Additional server-side validation
            is_valid, message = validate_password_strength(form.new_password.data)
            if not is_valid:
                flash(message, 'danger')
                return render_template('change_password.html', title='Change Password', form=form)
            
            current_user.set_password(form.new_password.data)
            db.session.commit()
            
            log_audit('password_changed', 'user', str(current_user.id), "User changed password")
            
            flash('Your password has been updated!', 'success')
            return redirect(url_for('main.index'))
        else:
            flash('Current password is incorrect.', 'danger')
    
    return render_template('change_password.html', title='Change Password', form=form)

@auth.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    """Request password reset route"""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # Generate token
            token = secrets.token_hex(16)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            
            # Store token in session (in a real app, this would be stored in the database)
            session['reset_token'] = token_hash
            session['reset_email'] = user.email
            session['reset_expiry'] = (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp()
            
            log_audit('password_reset_requested', 'user', str(user.id), f"Password reset requested for {user.email}")
            
            # In a real app, send email with reset link
            # For this demo, we'll just redirect to the reset page with the token
            flash('Password reset instructions have been sent to your email.', 'info')
            return redirect(url_for('auth.reset_password', token=token))
        else:
            # Don't reveal if email exists (security best practice)
            flash('If that email address exists in our database, we have sent you instructions to reset your password.', 'info')
    
    return render_template('reset_password_request.html', title='Reset Password', form=form)

@auth.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password route"""
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    # Verify token
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    stored_token = session.get('reset_token')
    stored_email = session.get('reset_email')
    expiry = session.get('reset_expiry')
    
    if not stored_token or not stored_email or not expiry:
        flash('Invalid or expired reset link.', 'danger')
        return redirect(url_for('auth.login'))
    
    if token_hash != stored_token:
        flash('Invalid reset link.', 'danger')
        return redirect(url_for('auth.login'))
    
    if datetime.datetime.utcnow().timestamp() > expiry:
        # Clear session data
        session.pop('reset_token', None)
        session.pop('reset_email', None)
        session.pop('reset_expiry', None)
        
        flash('Reset link has expired.', 'danger')
        return redirect(url_for('auth.login'))
    
    user = User.query.filter_by(email=stored_email).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('auth.login'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        # Additional server-side validation
        is_valid, message = validate_password_strength(form.password.data)
        if not is_valid:
            flash(message, 'danger')
            return render_template('reset_password.html', title='Reset Password', form=form)
        
        user.set_password(form.password.data)
        user.reset_login_attempts()
        db.session.commit()
        
        # Clear session data
        session.pop('reset_token', None)
        session.pop('reset_email', None)
        session.pop('reset_expiry', None)
        
        log_audit('password_reset_completed', 'user', str(user.id), f"Password reset completed for {user.email}")
        
        flash('Your password has been reset!', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('reset_password.html', title='Reset Password', form=form)

@auth.route('/profile')
@login_required
def profile():
    """User profile route"""
    return render_template('profile.html', title='Profile')

@auth.route('/admin')
@login_required
@admin_required
def admin_panel():
    """Admin panel route"""
    users = User.query.all()
    login_logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(50).all()
    audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    
    return render_template('admin.html', title='Admin Panel', 
                          users=users, login_logs=login_logs, audit_logs=audit_logs)
