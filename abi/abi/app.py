import os
import logging
import traceback
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time

app = Flask(__name__)

# Initialize Flask-Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Configuration
app.config["SECRET_KEY"] = "12345678900987654123456781234567"  # 32-byte key
basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///' + os.path.join(basedir, 'myshop.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Console handler for general logs
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_formatter = logging.Formatter('%(levelname)s: %(message)s')
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

# File handler for DDoS attack logs
file_handler = logging.FileHandler('ddos_attack.log')
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)

# Add a specific logger for DDoS attacks
ddos_logger = logging.getLogger('ddos')
ddos_logger.setLevel(logging.INFO)
ddos_logger.addHandler(file_handler)

# Blacklist IPs
blacklisted_ips = set()
ip_request_times = {}

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)

# AES encryption functions
def encrypt_password(password, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(password.encode('utf-8'), AES.block_size))
    return cipher.iv + ct_bytes

def decrypt_password(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# IP Blacklisting
@app.before_request
def block_blacklisted_ips():
    ip = request.remote_addr
    if ip in blacklisted_ips:
        ddos_logger.info(f"Blocked request from blacklisted IP: {ip}")
        return "Your IP is blacklisted.", 403

@app.before_request
def throttle_requests():
    ip = request.remote_addr
    now = time.time()
    if ip not in ip_request_times:
        ip_request_times[ip] = []
    
    # Remove timestamps older than 60 seconds
    ip_request_times[ip] = [timestamp for timestamp in ip_request_times[ip] if now - timestamp < 60]
    
    # Check if the IP has made more than 100 requests in the last 60 seconds
    if len(ip_request_times[ip]) > 100:
        blacklisted_ips.add(ip)
        ddos_logger.info(f"IP {ip} rate limited and added to blacklist due to excessive requests.")
        return "Rate limit exceeded. Your IP is blacklisted.", 429
    
    # Record the current timestamp
    ip_request_times[ip].append(now)

# Routes
@app.route('/')
@limiter.limit("10 per minute")  # Adjust the limit as needed
def home():
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Adjust the limit as needed
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            decrypted_password = decrypt_password(user.password, app.config["SECRET_KEY"].encode('utf-8'))
            if decrypted_password == password:
                login_user(user)
                flash('Logged in successfully.', 'success')
                return redirect(url_for('home'))
        flash('Login failed. Check your email and password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        if current_user.is_authenticated:
            return redirect(url_for('home'))
        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            encrypted_password = encrypt_password(password, app.config["SECRET_KEY"].encode('utf-8'))
            user = User(username=username, email=email, password=encrypted_password)
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('login'))
        return render_template('register.html')
    except Exception as e:
        app.logger.error(f"Error in register route: {e}, traceback: {traceback.format_exc()}")
        return render_template('500.html'), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        name = request.form.get('name')
        price = request.form.get('price')
        description = request.form.get('description')
        product = Product(name=name, price=price, description=description)
        db.session.add(product)
        db.session.commit()
        flash('Product has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('product_form.html')

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)

@app.route('/blacklist_ip', methods=['POST'])
@login_required
def blacklist_ip():
    ip = request.form.get('ip')
    if ip:
        blacklisted_ips.add(ip)
        ddos_logger.info(f"Blacklisted IP: {ip}")
        flash('IP has been blacklisted.', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
