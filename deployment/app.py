"""
Enhanced app.py with integrated security features
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort
from flask_login import LoginManager, current_user, login_required
import os
import json
import datetime
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman

# Import application modules
from stock_data import StockData
from drop_detector import DropDetector
from ath_detector import ATHDetector
from models import db, User, init_db
from auth import auth
from security import log_security_event, is_rate_limited, sanitize_input

# Create Flask application
app = Flask(__name__)

# Security configuration
app.config['SECRET_KEY'] = os.urandom(32)  # Strong random secret key
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=1)  # Session timeout
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_DURATION'] = datetime.timedelta(days=14)
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour
app.config['JSON_SORT_KEYS'] = False  # Prevent JSON parameter tampering

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stock_tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'info'

# Initialize Talisman for security headers
csp = {
    'default-src': "'self'",
    'script-src': ["'self'", 'https://cdn.jsdelivr.net'],
    'style-src': ["'self'", 'https://cdn.jsdelivr.net'],
    'img-src': ["'self'", 'data:'],
    'font-src': ["'self'", 'https://cdn.jsdelivr.net'],
    'connect-src': "'self'"
}
talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src'],
    feature_policy={
        'geolocation': "'none'",
        'microphone': "'none'",
        'camera': "'none'"
    },
    force_https=True,
    force_https_permanent=True,
    session_cookie_secure=True,
    session_cookie_http_only=True,
    strict_transport_security=True,
    strict_transport_security_preload=True,
    strict_transport_security_max_age=31536000,
    referrer_policy='strict-origin-when-cross-origin'
)

# Fix for proper IP address behind proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Initialize data services
stock_data = StockData()
drop_detector = DropDetector()
ath_detector = ATHDetector()

# Register blueprints
app.register_blueprint(auth, url_prefix='/auth')

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Security middleware
@app.before_request
def before_request():
    # Rate limiting
    if request.endpoint and not request.endpoint.startswith('static'):
        # Different rate limits for different endpoints
        if request.endpoint == 'auth.login':
            # Stricter rate limiting for login attempts
            if is_rate_limited(f"login:{request.remote_addr}", limit=5, period=300):
                log_security_event('rate_limit_exceeded', details=f"Login rate limit exceeded for IP: {request.remote_addr}")
                abort(429)  # Too Many Requests
        else:
            # General rate limiting
            if is_rate_limited(request.remote_addr, limit=30, period=60):
                log_security_event('rate_limit_exceeded', details=f"General rate limit exceeded for IP: {request.remote_addr}")
                abort(429)  # Too Many Requests
    
    # Set secure headers for all responses
    session.permanent = True
    
    # Log request for security monitoring
    if not request.path.startswith('/static'):
        log_security_event('request', 
                          user_id=current_user.id if current_user.is_authenticated else None,
                          details=f"Path: {request.path}, Method: {request.method}")

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    log_security_event('error_404', details=f"Path: {request.path}")
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    log_security_event('error_403', details=f"Path: {request.path}")
    return render_template('errors/403.html'), 403

@app.errorhandler(429)
def too_many_requests(e):
    return render_template('errors/429.html'), 429

@app.errorhandler(500)
def internal_server_error(e):
    log_security_event('error_500', details=f"Path: {request.path}, Error: {str(e)}")
    return render_template('errors/500.html'), 500

# Main routes
@app.route('/')
def index():
    """Render the main dashboard page"""
    return render_template('index.html')

# API routes with authentication and security
@app.route('/api/stock/<symbol>')
@login_required
def get_stock(symbol):
    """API endpoint to get stock data"""
    # Sanitize and validate input
    symbol = sanitize_input(symbol)
    if not symbol or len(symbol) > 10:
        return jsonify({'error': 'Invalid symbol'}), 400
    
    interval = sanitize_input(request.args.get('interval', '1d'))
    range_param = sanitize_input(request.args.get('range', '1y'))
    
    # Log API access
    log_security_event('api_access', 
                      user_id=current_user.id,
                      details=f"Stock data requested for {symbol}")
    
    data = stock_data.get_stock_history(symbol, interval, range_param)
    return jsonify(data)

@app.route('/api/drops/<symbol>')
@login_required
def get_drops(symbol):
    """API endpoint to get stock drops"""
    # Sanitize and validate input
    symbol = sanitize_input(symbol)
    if not symbol or len(symbol) > 10:
        return jsonify({'error': 'Invalid symbol'}), 400
    
    try:
        threshold = float(request.args.get('threshold', '-0.03'))
        days = int(request.args.get('days', '90'))
        consecutive = request.args.get('consecutive', 'false').lower() == 'true'
        
        # Validate numeric parameters
        if days <= 0 or days > 365:
            return jsonify({'error': 'Invalid days parameter'}), 400
        if threshold > 0:
            return jsonify({'error': 'Threshold must be negative'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid numeric parameters'}), 400
    
    # Log API access
    log_security_event('api_access', 
                      user_id=current_user.id,
                      details=f"Drops data requested for {symbol}")
    
    # Use enhanced drop detector
    drops = drop_detector.detect_drops(symbol, threshold, days, consecutive)
    return jsonify(drops)

@app.route('/api/drops/market-analysis/<symbol>')
@login_required
def get_market_analysis(symbol):
    """API endpoint to get market condition analysis for drops"""
    # Sanitize and validate input
    symbol = sanitize_input(symbol)
    if not symbol or len(symbol) > 10:
        return jsonify({'error': 'Invalid symbol'}), 400
    
    index_symbol = sanitize_input(request.args.get('index', '^GSPC'))
    
    try:
        days = int(request.args.get('days', '90'))
        if days <= 0 or days > 365:
            return jsonify({'error': 'Invalid days parameter'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid days parameter'}), 400
    
    # Log API access
    log_security_event('api_access', 
                      user_id=current_user.id,
                      details=f"Market analysis requested for {symbol}")
    
    analysis = drop_detector.analyze_market_conditions(symbol, index_symbol, days)
    return jsonify(analysis)

@app.route('/api/drops/statistics/<symbol>')
@login_required
def get_drop_statistics(symbol):
    """API endpoint to get historical drop statistics"""
    # Sanitize and validate input
    symbol = sanitize_input(symbol)
    if not symbol or len(symbol) > 10:
        return jsonify({'error': 'Invalid symbol'}), 400
    
    try:
        years = int(request.args.get('years', '3'))
        if years <= 0 or years > 10:
            return jsonify({'error': 'Invalid years parameter'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid years parameter'}), 400
    
    # Log API access
    log_security_event('api_access', 
                      user_id=current_user.id,
                      details=f"Drop statistics requested for {symbol}")
    
    statistics = drop_detector.calculate_drop_statistics(symbol, years)
    return jsonify(statistics)

@app.route('/api/ath/<symbol>')
@login_required
def get_all_time_highs(symbol):
    """API endpoint to get all-time highs"""
    # Sanitize and validate input
    symbol = sanitize_input(symbol)
    if not symbol or len(symbol) > 10:
        return jsonify({'error': 'Invalid symbol'}), 400
    
    range_param = sanitize_input(request.args.get('range', '1y'))
    
    # Log API access
    log_security_event('api_access', 
                      user_id=current_user.id,
                      details=f"ATH data requested for {symbol}")
    
    # Use enhanced ATH detector
    ath = ath_detector.detect_all_time_highs(symbol, range_param)
    return jsonify(ath)

@app.route('/api/ath/breakouts/<symbol>')
@login_required
def get_ath_breakouts(symbol):
    """API endpoint to get ATH breakout analysis"""
    # Sanitize and validate input
    symbol = sanitize_input(symbol)
    if not symbol or len(symbol) > 10:
        return jsonify({'error': 'Invalid symbol'}), 400
    
    try:
        years = int(request.args.get('years', '3'))
        if years <= 0 or years > 10:
            return jsonify({'error': 'Invalid years parameter'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid years parameter'}), 400
    
    # Log API access
    log_security_event('api_access', 
                      user_id=current_user.id,
                      details=f"ATH breakouts requested for {symbol}")
    
    breakouts = ath_detector.analyze_ath_breakouts(symbol, years)
    return jsonify(breakouts)

@app.route('/api/ath/sector-comparison/<symbol>')
@login_required
def get_sector_comparison(symbol):
    """API endpoint to get sector comparison for ATH performance"""
    # Sanitize and validate input
    symbol = sanitize_input(symbol)
    if not symbol or len(symbol) > 10:
        return jsonify({'error': 'Invalid symbol'}), 400
    
    sector_etf = sanitize_input(request.args.get('sector_etf', None))
    
    # Log API access
    log_security_event('api_access', 
                      user_id=current_user.id,
                      details=f"Sector comparison requested for {symbol}")
    
    comparison = ath_detector.compare_sector_performance(symbol, sector_etf)
    return jsonify(comparison)

@app.route('/api/insights/<symbol>')
@login_required
def get_insights(symbol):
    """API endpoint to get stock insights"""
    # Sanitize and validate input
    symbol = sanitize_input(symbol)
    if not symbol or len(symbol) > 10:
        return jsonify({'error': 'Invalid symbol'}), 400
    
    # Log API access
    log_security_event('api_access', 
                      user_id=current_user.id,
                      details=f"Insights requested for {symbol}")
    
    insights = stock_data.get_stock_insights(symbol)
    return jsonify(insights)

@app.route('/api/watchlist')
@login_required
def get_watchlist():
    """API endpoint to get watchlist stocks"""
    # Get user's watchlist
    from models import Watchlist, WatchlistStock
    
    # Find user's default watchlist
    watchlist = Watchlist.query.filter_by(user_id=current_user.id).first()
    
    if not watchlist:
        # Create default watchlist if none exists
        watchlist = Watchlist(name='Default', user_id=current_user.id)
        db.session.add(watchlist)
        db.session.commit()
    
    # Get stocks from watchlist
    watchlist_stocks = WatchlistStock.query.filter_by(watchlist_id=watchlist.id).all()
    symbols = [stock.symbol for stock in watchlist_stocks]
    
    if not symbols:
        # Add default stocks if watchlist is empty
        default_stocks = ['AAPL', 'MSFT', 'GOOGL', 'AMZN', 'META']
        for symbol in default_stocks:
            stock = WatchlistStock(symbol=symbol, watchlist_id=watchlist.id)
            db.session.add(stock)
        db.session.commit()
        symbols = default_stocks
    
    # Get data for each stock in watchlist
    results = []
    for symbol in symbols:
        data = stock_data.get_stock_history(symbol, interval='1d', range='5d')
        if 'error' not in data:
            stock_info = {
                'symbol': symbol,
                'name': data.get('name', symbol),
                'current_price': data.get('current_price'),
                'all_time_high': data.get('all_time_high'),
                'pct_from_ath': data.get('pct_from_ath'),
                'significant_drops': data.get('significant_drops', [])
            }
            results.append(stock_info)
    
    # Log API access
    log_security_event('api_access', 
                      user_id=current_user.id,
                      details="Watchlist data requested")
    
    return jsonify(results)

@app.route('/api/watchlist/add', methods=['POST'])
@login_required
@csrf.exempt  # CSRF protection handled manually
def add_to_watchlist():
    """API endpoint to add stock to watchlist"""
    # Verify CSRF token
    token = request.json.get('csrf_token')
    if token != session.get('csrf_token'):
        log_security_event('csrf_failure', 
                          user_id=current_user.id,
                          details="CSRF token validation failed on watchlist add")
        return jsonify({'error': 'Invalid CSRF token'}), 403
    
    # Get and validate data
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    symbol = sanitize_input(data.get('symbol', '').upper())
    
    if not symbol:
        return jsonify({'error': 'No symbol provided'}), 400
    
    if len(symbol) > 10:
        return jsonify({'error': 'Symbol too long'}), 400
    
    # Validate symbol by fetching data
    check = stock_data.get_stock_history(symbol)
    if 'error' in check:
        return jsonify({'error': f'Invalid symbol: {symbol}'}), 400
    
    # Get user's watchlist
    from models import Watchlist, WatchlistStock
    
    # Find user's default watchlist
    watchlist = Watchlist.query.filter_by(user_id=current_user.id).first()
    
    if not watchlist:
        # Create default watchlist if none exists
        watchlist = Watchlist(name='Default', user_id=current_user.id)
        db.session.add(watchlist)
        db.session.commit()
    
    # Check if symbol already in watchlist
    existing = WatchlistStock.query.filter_by(
        watchlist_id=watchlist.id, 
        symbol=symbol
    ).first()
    
    if existing:
        return jsonify({'success': False, 'message': f'{symbol} already in watchlist'})
    
    # Add symbol to watchlist
    stock = WatchlistStock(symbol=symbol, watchlist_id=watchlist.id)
    db.session.add(stock)
    db.session.commit()
    
    # Log action
    log_security_event('watchlist_add', 
                      user_id=current_user.id,
                      details=f"Added {symbol} to watchlist")
    
    return jsonify({'success': True, 'message': f'Added {symbol} to watchlist'})

@app.route('/api/watchlist/remove', methods=['POST'])
@login_required
@csrf.exempt  # CSRF protection handled manually
def remove_from_watchlist():
    """API endpoint to remove stock from watchlist"""
    # Verify CSRF token
    token = request.json.get('csrf_token')
    if token != session.get('csrf_token'):
        log_security_event('csrf_failure', 
                          user_id=current_user.id,
                          details="CSRF token validation failed on watchlist remove")
        return jsonify({'error': 'Invalid CSRF token'}), 403
    
    # Get and validate data
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    symbol = sanitize_input(data.get('symbol', '').upper())
    
    if not symbol:
        return jsonify({'error': 'No symbol provided'}), 400
    
    # Get user's watchlist
    from models import Watchlist, WatchlistStock
    
    # Find user's default watchlist
    watchlist = Watchlist.query.filter_by(user_id=current_user.id).first()
    
    if not watchlist:
        return jsonify({'success': False, 'message': 'Watchlist not found'})
    
    # Find stock in watchlist
    stock = WatchlistStock.query.filter_by(
        watchlist_id=watchlist.id, 
        symbol=symbol
    ).first()
    
    if not stock:
        return jsonify({'success': False, 'message': f'{symbol} not in watchlist'})
    
    # Remove stock from watchlist
    db.session.delete(stock)
    db.session.commit()
    
    # Log action
    log_security_event('watchlist_remove', 
                      user_id=current_user.id,
                      details=f"Removed {symbol} from watchlist")
    
    return jsonify({'success': True, 'message': f'Removed {symbol} from watchlist'})

# Main route for authenticated dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    """Render the authenticated dashboard page"""
    return render_template('dashboard.html')

# Main entry point
if __name__ == '__main__':
    # Create directories if they don't exist
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    if not os.path.exists('static'):
        os.makedirs('static')
        os.makedirs('static/css', exist_ok=True)
        os.makedirs('static/js', exist_ok=True)
    
    # Initialize database and create admin user
    with app.app_context():
        init_db(app)
    
    # Run the application with HTTPS in development
    app.run(
        host='0.0.0.0', 
        port=5000, 
        ssl_context='adhoc',  # Use adhoc SSL for development
        debug=False  # Disable debug mode for security
    )
