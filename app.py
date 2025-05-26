from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
from flask_login import login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives import hashes
from sqlalchemy import Column, Integer, String, DateTime, LargeBinary
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from urllib.parse import urlencode, quote_plus
from flask import redirect
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pyotp
import os
import base64
import pymysql  # Add this import to fix the NameError
import qrcode
from io import BytesIO
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import requests
from requests_oauthlib import OAuth2Session
from werkzeug.security import generate_password_hash, check_password_hash
import re
import pytz
from werkzeug.utils import secure_filename
import hmac
import hashlib

app = Flask(__name__)
load_dotenv()

# Application configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/securedocs'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['CERTS_FOLDER'] = 'certs'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5000000)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['CERTS_FOLDER'], exist_ok=True)
db = SQLAlchemy(app)

# Load or generate AES encryption key
def load_or_generate_key():
    key_file = os.path.join(app.config['CERTS_FOLDER'], 'aes_key.key')
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    key = os.urandom(32)  # AES-256 key
    with open(key_file, 'wb') as f:
        f.write(key)
    return key
AES_KEY = load_or_generate_key()

# Load or generate HMAC key
def load_or_generate_hmac_key():
    key_file = os.path.join(app.config['CERTS_FOLDER'], 'hmac_key.key')
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    key = os.urandom(32)
    with open(key_file, 'wb') as f:
        f.write(key)
    return key
HMAC_KEY = load_or_generate_hmac_key()

# RSA key pair generation and storage
def generate_key_pair(user_id):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save keys to CERTS_FOLDER
    private_path = os.path.join(app.config['CERTS_FOLDER'], f'private_{user_id}.pem')
    public_path = os.path.join(app.config['CERTS_FOLDER'], f'public_{user_id}.pem')

    with open(private_path, 'wb') as f:
        f.write(private_pem)
    with open(public_path, 'wb') as f:
        f.write(public_pem)

    return private_key, public_key


def load_private_key(user_id):
    try:
        with open(os.path.join(app.config['CERTS_FOLDER'], f'private_{user_id}.pem'), 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    except FileNotFoundError:
        return None

def load_public_key(user_id):
    try:
        with open(os.path.join(app.config['CERTS_FOLDER'], f'public_{user_id}.pem'), 'rb') as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())
    except FileNotFoundError:
        return None

# Encryption and signing utilities
def encrypt_file(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = data + b' ' * (16 - len(data) % 16)
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def decrypt_file(encrypted_data, key):
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    return decrypted_padded.rstrip(b' ')

def generate_hash(data):
    return hashlib.sha256(data).hexdigest()

def generate_hmac(data, key):
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def verify_hmac(data, key, hmac_value):
    return hmac.new(key, data, hashlib.sha256).hexdigest() == hmac_value

def sign_file(data, private_key):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(data, signature, public_key):
    try:
        public_key.verify(
            base64.b64decode(signature),
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verify error: {e}")
        return False



# Okta OIDC configuration
OKTA_CLIENT_ID = os.getenv('OKTA_CLIENT_ID')
OKTA_CLIENT_SECRET = os.getenv('OKTA_CLIENT_SECRET')
OKTA_ISSUER = os.getenv('OKTA_ISSUER')
OKTA_REDIRECT_URI = "https://localhost:5000/auth/okta/callback"
OKTA_AUTHORIZATION_URL = f"{OKTA_ISSUER}/v1/authorize"
OKTA_TOKEN_URL = f"{OKTA_ISSUER}/v1/token"
OKTA_USERINFO_URL = f"{OKTA_ISSUER}/v1/userinfo"

# Database models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    role = db.Column(db.Enum('user', 'admin'), default='user')
    two_factor_secret = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password) if self.password_hash else False

class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    hmac = db.Column(db.String(64), nullable=False)
    encrypted_data = db.Column(db.LargeBinary(length=16777215), nullable=False)
    signature = db.Column(db.Text, nullable=False)
    uploaded_at = Column(DateTime, default=datetime.now, nullable=False)
    user = db.relationship('User', backref='documents')

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='audit_logs')

# Password strength validation
def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    return True

# Login required decorator
def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('login'))

        # استثناء لمسار 2FA
        if request.endpoint not in ['verify2fa', 'setup2fa'] and not session.get('two_factor_authenticated'):
            return redirect(url_for('verify2fa'))

        session_start = session.get('session_start')
        if session_start:
            start_time = datetime.fromisoformat(session_start).replace(tzinfo=None)
            if (datetime.utcnow() - start_time) > app.config['PERMANENT_SESSION_LIFETIME']:
                session.clear()
                flash('Session expired. Please log in again.', 'error')
                return redirect(url_for('login'))

        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap


# Routes
@app.route('/change_role/<int:user_id>', methods=['POST'])
@login_required
def change_role(user_id):
    # الحصول على المستخدم الحالي من السيشن
    current_user = db.session.get(User, session['user_id'])

    if current_user.role != 'admin':
        flash("You don't have permission to change roles.", "error")
        return redirect(url_for('admin'))

    new_role = request.form.get('role')
    if new_role not in ['user', 'admin']:
        flash('Invalid role selected.', 'error')
        return redirect(url_for('admin'))

    # جلب المستخدم من قاعدة البيانات حسب الـ user_id
    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin'))

    user.role = new_role
    db.session.commit()

    flash('User role updated successfully.', 'success')
    return redirect(url_for('admin'))


@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['session_start'] = datetime.utcnow().isoformat()
            
            # تعيين مدة الجلسة بناءً على اختيار "تذكرني"
            if remember:
                # تعيين مدة الجلسة ليوم واحد
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=1)
            else:
                # استخدام المدة الافتراضية (5000000 دقيقة كما هو محدد في الإعدادات)
                session.permanent = True
            
            log = AuditLog(user_id=user.id, action=f'User {user.username} logged in')
            db.session.add(log)
            db.session.commit()

            # لو الادمن ما فعّلش 2FA يروح للـ setup
            if user.role == 'admin' and not user.two_factor_secret:
                flash('Please setup 2FA first, Admin!', 'info')
                return redirect(url_for('setup2fa'))

            # لو فعّل 2FA يروح لعملية التحقق (verify)
            if user.two_factor_secret:
                return redirect(url_for('verify2fa'))

            # لو مش ادمن أو مش مفعل 2FA يروح للداشبورد
            return redirect(url_for('dashboard'))

        flash('Invalid email or password.', 'error')
    return render_template('login.html', bootstrap=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # التأكد إن username مش فاضي
        if not username:
            flash('Username is required.', 'error')
            return render_template('register.html', bootstrap=True)
        
        # باقي الكود زي ما هو
        if not is_strong_password(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, and numbers.', 'error')
            return render_template('register.html', bootstrap=True)
        if User.query.filter_by(email=email).first():
            flash('Email is already in use.', 'error')
            return render_template('register.html', bootstrap=True)
        if User.query.filter_by(username=username).first():
            flash('Username is already taken.', 'error')
            return render_template('register.html', bootstrap=True)
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', bootstrap=True)
@app.route('/auth/google')
def google_auth():
    auth_url = (
        f"https://accounts.google.com/o/oauth2/auth?response_type=code&client_id="
        f"{os.getenv('GOOGLE_CLIENT_ID')}&redirect_uri=https://localhost:5000/auth/google/callback&scope=email%20profile"
    )
    return redirect(auth_url)

@app.route('/auth/google/callback')
def google_callback():
    try:
        code = request.args.get('code')
        token_url = "https://oauth2.googleapis.com/token"
        token_data = {
            "code": code,
            "client_id": os.getenv('GOOGLE_CLIENT_ID'),
            "client_secret": os.getenv('GOOGLE_CLIENT_SECRET'),
            "redirect_uri": "https://localhost:5000/auth/google/callback",
            "grant_type": "authorization_code",
        }
        response = requests.post(token_url, data=token_data)
        response.raise_for_status()
        token_json = response.json()
        access_token = token_json.get('access_token')
        if not access_token:
            flash('Failed to obtain access token from Google.', 'error')
            return redirect(url_for('login'))
        user_info = requests.get(f"https://www.googleapis.com/oauth2/v1/userinfo?access_token={access_token}").json()
        email = user_info.get('email')
        username = user_info.get('name')
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(username=username, email=email, role='user')
            user.set_password(os.urandom(16).hex())
            db.session.add(user)
            db.session.commit()
        session['user_id'] = user.id
        session['session_start'] = datetime.utcnow().isoformat()
        session.permanent = True
        log = AuditLog(user_id=user.id, action=f'User {user.username} logged in via Google')
        db.session.add(log)
        db.session.commit()
        if user.two_factor_secret:
            return redirect(url_for('verify2fa'))
        return redirect(url_for('setup2fa'))
    except Exception as e:
        flash(f'Error during Google authentication: {str(e)}', 'error')
        return redirect(url_for('login'))

@app.route('/auth/github')
def github_auth():
    auth_url = (
        f"https://github.com/login/oauth/authorize?client_id="
        f"{os.getenv('GITHUB_CLIENT_ID')}&redirect_uri=https://localhost:5000/auth/github/callback&scope=user:email"
    )
    return redirect(auth_url)

@app.route('/auth/github/callback')
def github_callback():
    try:
        code = request.args.get('code')
        token_url = "https://github.com/login/oauth/access_token"
        token_data = {
            "client_id": os.getenv('GITHUB_CLIENT_ID'),
            "client_secret": os.getenv('GITHUB_CLIENT_SECRET'),
            "code": code,
            "redirect_uri": "https://localhost:5000/auth/github/callback",
        }
        headers = {'Accept': 'application/json'}
        response = requests.post(token_url, data=token_data, headers=headers)
        response.raise_for_status()
        token_json = response.json()
        access_token = token_json.get('access_token')
        if not access_token:
            flash('No access token received from GitHub.', 'error')
            return redirect(url_for('login'))
        user_info = requests.get("https://api.github.com/user", headers={"Authorization": f"Bearer {access_token}"}).json()
        email_response = requests.get("https://api.github.com/user/emails", headers={"Authorization": f"Bearer {access_token}"})
        email_response.raise_for_status()
        emails = email_response.json()
        email = next((email['email'] for email in emails if email.get('primary', False) and email.get('verified', False)), None)
        if not email:
            flash('No verified primary email found.', 'error')
            return redirect(url_for('login'))
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(username=user_info.get('login'), email=email, role='user')
            user.set_password(os.urandom(16).hex())
            db.session.add(user)
            db.session.commit()
        session['user_id'] = user.id
        session['session_start'] = datetime.utcnow().isoformat()
        session.permanent = True
        log = AuditLog(user_id=user.id, action=f'User {user.username} logged in via GitHub')
        db.session.add(log)
        db.session.commit()
        if user.two_factor_secret:
            return redirect(url_for('verify2fa'))
        return redirect(url_for('setup2fa'))
    except Exception as e:
        flash(f'Error during GitHub authentication: {str(e)}', 'error')
        return redirect(url_for('login'))

from datetime import datetime, timezone

from datetime import datetime, timezone

@app.route('/auth/okta')
def okta_auth():
    try:
        # إجبار Okta على إظهار شاشة تسجيل الدخول كل مرة
        okta = OAuth2Session(
            OKTA_CLIENT_ID,
            redirect_uri=OKTA_REDIRECT_URI,
            scope=["openid", "email", "profile"]
        )
        authorization_url, state = okta.authorization_url(
            OKTA_AUTHORIZATION_URL,
            prompt='login'  # مهم لفرض شاشة تسجيل الدخول
        )
        session['oauth_state'] = state
        return redirect(authorization_url)
    except Exception as e:
        flash(f'Error initiating Okta login: {str(e)}', 'error')
        return redirect(url_for('login'))

@app.route('/auth/okta/callback')
def okta_callback():
    try:
        if 'oauth_state' not in session:
            flash('Invalid state parameter. Session may have expired.', 'error')
            return redirect(url_for('login'))

        # جلب التوكن بعد العودة من Okta
        okta = OAuth2Session(
            OKTA_CLIENT_ID,
            state=session['oauth_state'],
            redirect_uri=OKTA_REDIRECT_URI
        )
        token = okta.fetch_token(
            OKTA_TOKEN_URL,
            client_secret=OKTA_CLIENT_SECRET,
            code=request.args.get('code')
        )

        # جلب بيانات المستخدم من Okta
        okta = OAuth2Session(OKTA_CLIENT_ID, token=token)
        user_info = okta.get(OKTA_USERINFO_URL).json()

        email = user_info.get('email')
        if not email:
            flash('No email found in Okta user info.', 'error')
            return redirect(url_for('login'))

        # التحقق أو إنشاء مستخدم
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(
                username=user_info.get('preferred_username', email),
                email=email,
                role='user'
            )
            user.set_password(os.urandom(16).hex())  # كلمة مرور عشوائية
            db.session.add(user)
            db.session.commit()

        # تسجيل الدخول في الجلسة
        session['user_id'] = user.id
        session['session_start'] = datetime.now(timezone.utc).isoformat()
        session.permanent = True

        # لوج التدقيق
        log = AuditLog(user_id=user.id, action=f'User {user.username} logged in via Okta')
        db.session.add(log)
        db.session.commit()

        # توجيه حسب حالة 2FA
        if not user.two_factor_secret:
            return redirect(url_for('setup2fa'))
        else:
            return redirect(url_for('verify2fa'))

    except Exception as e:
        flash(f'Error during Okta callback: {str(e)}', 'error')
        return redirect(url_for('login'))


@app.route('/setup2fa', methods=['GET', 'POST'])
def setup2fa():
    if 'user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    if not user:
        flash('User not found. Please log in again.', 'error')
        # بدال session.clear()
        session.pop('user_id', None)
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form.get('token')
        temp_secret = session.get('temp_2fa_secret')
        if not temp_secret:
            flash('2FA setup session expired. Please try again.', 'error')
            return redirect(url_for('setup2fa'))

        totp = pyotp.TOTP(temp_secret)
        if totp.verify(token, valid_window=1):
            user.two_factor_secret = temp_secret
            db.session.commit()
            session.pop('temp_2fa_secret', None)
            session['two_factor_authenticated'] = True  # مباشرةً بعد النجاح
            session.permanent = True
            flash('2FA setup completed successfully.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid 2FA token. Ensure your device time is synchronized.', 'error')

    if not user.two_factor_secret:
        secret = pyotp.random_base32()
        session['temp_2fa_secret'] = secret
        totp = pyotp.TOTP(secret)
        qr_url = totp.provisioning_uri(user.email, issuer_name="SecureDocs")
        qr = qrcode.make(qr_url)
        buffer = BytesIO()
        qr.save(buffer, format="PNG")
        qr_code = base64.b64encode(buffer.getvalue()).decode('utf-8')
        return render_template('setup2fa.html', qr_code=qr_code, user=user, bootstrap=True)

    return redirect(url_for('verify2fa'))



@app.route('/verify2fa', methods=['GET', 'POST'])
def verify2fa():
    if 'user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    if not user or not user.two_factor_secret:
        flash('2FA not configured. Please set up 2FA first.', 'error')
        return redirect(url_for('setup2fa'))

    totp = pyotp.TOTP(user.two_factor_secret)

    if request.method == 'POST':
        token = request.form.get('token')
        if totp.verify(token, valid_window=1):
            session['two_factor_authenticated'] = True
            session.permanent = True
            flash('2FA verification successful.', 'success')
            print("✅ Session after 2FA verify:", dict(session))  # مؤقتًا للمراقبة
            return redirect(url_for('dashboard'))
        flash('Invalid 2FA token. Ensure your device time is synchronized.', 'error')

    return render_template('verify2fa.html', user=user, bootstrap=True)



@app.route('/dashboard')
@login_required
def dashboard():
    if not session.get('two_factor_authenticated'):
        flash("You must complete 2FA verification to access the dashboard.", "error")
        return redirect(url_for('verify2fa'))

    user = db.session.get(User, session['user_id'])
    documents = Document.query.filter_by(user_id=user.id).all()
    total_docs = len(documents)
    recent_docs = Document.query.filter_by(user_id=user.id).order_by(Document.uploaded_at.desc()).limit(5).all()
    return render_template('dashboard.html', user=user, documents=documents, total_docs=total_docs, recent_docs=recent_docs, bootstrap=True)

@app.route('/documents')
@login_required
def documents():
    user = db.session.get(User, session['user_id'])
    user_docs = Document.query.filter_by(user_id=user.id).all()
    return render_template('documents.html', user=user, documents=user_docs, bootstrap=True)



@app.route('/edit_filename/<int:doc_id>', methods=['POST'])
@login_required
def edit_filename(doc_id):
    document = Document.query.get_or_404(doc_id)
    
    # التحقق من صلاحية التعديل
    if session.get('role') != 'admin' and document.user_id != session.get('user_id'):
        flash('You are not authorized to edit this document.', 'error')
        return redirect(url_for('documents'))

    new_name = request.form.get('filename')
    if not new_name:
        flash('Filename cannot be empty.', 'error')
        return redirect(url_for('documents'))
    
    # التأكد من إن اسم الملف آمن
    new_name = secure_filename(new_name.strip())
    if not new_name.lower().endswith(('.pdf', '.docx', '.txt')):
        flash('Filename must end with .pdf, .docx, or .txt.', 'error')
        return redirect(url_for('documents'))

    try:
        document.filename = new_name
        user = db.session.get(User, session['user_id'])
        log = AuditLog(user_id=user.id, action=f'User {user.username} edited document filename: {new_name}')
        db.session.add(log)
        db.session.commit()
        flash('Filename updated successfully.', 'success')
    except db.exc.OperationalError as e:
        db.session.rollback()
        flash(f'Database error: {str(e)}', 'error')

    return redirect(url_for('documents'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    user = db.session.get(User, session['user_id'])
    if request.method == 'POST':
        try:
            file = request.files.get('file')
            if not file or file.filename == '':
                flash('No file selected.', 'error')
                return redirect(url_for('upload'))

            if not file.filename.lower().endswith(('.pdf', '.docx', '.txt')):
                flash('Invalid file type. Only PDF, DOCX, and TXT are allowed.', 'error')
                return redirect(url_for('upload'))

            filename = secure_filename(file.filename)
            data = file.read()

            # التأكد من حجم الملف
            if len(data) > 16777215:
                flash('File too large. Maximum size is 16 MB.', 'error')
                return redirect(url_for('upload'))

            # توليد بيانات الملف
            file_hash = generate_hash(data)
            hmac_value = generate_hmac(data, HMAC_KEY)
            encrypted_data = encrypt_file(data, AES_KEY)

            # التحقق من حجم البيانات المشفرة
            if len(encrypted_data) > 16777215:
                flash('Encrypted file size exceeds database limits. Try a smaller file.', 'error')
                return redirect(url_for('upload'))

            private_key = load_private_key(user.id)
            if not private_key:
                private_key, _ = generate_key_pair(user.id)

            signature = sign_file(data, private_key)

            # إنشاء ملف جديد
            new_doc = Document(
                user_id=user.id,
                filename=filename,
                file_hash=file_hash,
                hmac=hmac_value,
                encrypted_data=encrypted_data,
                signature=signature,
                uploaded_at=datetime.now()  # تصحيح استخدام datetime
            )
            db.session.add(new_doc)
            log = AuditLog(user_id=user.id, action=f'User {user.username} uploaded document: {filename}')
            db.session.add(log)
            db.session.commit()
            flash('Document uploaded successfully.', 'success')
            return redirect(url_for('documents'))

        except pymysql.err.OperationalError as e:
            db.session.rollback()
            if "Lost connection to MySQL server" in str(e) or e.args[0] == 2013:
                flash('Database connection lost. Please try again.', 'error')
            elif "Packet too large" in str(e) or e.args[0] == 1153:
                flash('File size exceeds database packet limit. Try a smaller file or contact the administrator.', 'error')
            else:
                flash(f'Database error: {str(e)}', 'error')
            return redirect(url_for('upload'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'error')
            return redirect(url_for('upload'))

    return render_template('upload.html', user=user, bootstrap=True)

@app.route('/download/<int:id>')
@login_required
def download(id):
    doc = Document.query.get_or_404(id)
    user = db.session.get(User, session['user_id'])

    if doc.user_id != user.id and user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('documents'))

    decrypted = decrypt_file(doc.encrypted_data, AES_KEY)

    # DEBUG: Print hash values for comparison
    print("=== DEBUG ===")
    print("Stored file_hash in DB:            ", doc.file_hash)
    print("Hash of decrypted file (generated):", generate_hash(decrypted))

    # DEBUG: Save the decrypted file for manual inspection
    debug_path = os.path.join(app.config['UPLOAD_FOLDER'], "debug_decrypted_file.bin")
    with open(debug_path, "wb") as f:
        f.write(decrypted)
    print(f"Decrypted file saved to: {debug_path}")

    if not verify_hmac(decrypted, HMAC_KEY, doc.hmac):
        flash('Document integrity check failed (HMAC). The file may have been tampered with.', 'error')
        db.session.add(AuditLog(user_id=user.id, action=f'Integrity check failed (HMAC) for document: {doc.filename}'))
        db.session.commit()
        return redirect(url_for('documents'))

    if generate_hash(decrypted) != doc.file_hash:
        flash('Document integrity check failed (Hash). The file may have been tampered with.', 'error')
        db.session.add(AuditLog(user_id=user.id, action=f'Integrity check failed (Hash) for document: {doc.filename}'))
        db.session.commit()
        return redirect(url_for('documents'))

    public_key = load_public_key(doc.user_id)

    print("Public key loaded?", bool(public_key))
    print("Signature from DB (first 50 chars):", doc.signature[:50])

    if not public_key:
        flash('Missing public key.', 'error')
        return redirect(url_for('documents'))

    # DEBUG: Attempt signature verification and print result
    is_valid = verify_signature(decrypted, doc.signature, public_key)
    print("Signature verification result:", is_valid)

    if not is_valid:
        flash('Signature verification failed. The document may not be authentic.', 'error')
        db.session.add(AuditLog(user_id=user.id, action=f'Signature verification failed for document: {doc.filename}'))
        db.session.commit()
        return redirect(url_for('documents'))

    db.session.add(AuditLog(user_id=user.id, action=f'User {user.username} downloaded document: {doc.filename}'))
    db.session.commit()

    return Response(
        decrypted,
        mimetype='application/octet-stream',
        headers={"Content-Disposition": f"attachment; filename={doc.filename}"}
    )




@app.route('/delete_document/<int:id>')
@login_required
def delete_document_user(id):
    doc = Document.query.get_or_404(id)
    user = db.session.get(User, session['user_id'])
    if doc.user_id != user.id:
        flash('Access denied.', 'error')
        return redirect(url_for('documents'))
    db.session.delete(doc)
    log = AuditLog(user_id=user.id, action=f'User {user.username} deleted document: {doc.filename}')
    db.session.add(log)
    db.session.commit()
    flash('Document deleted successfully.', 'success')
    return redirect(url_for('documents'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = db.session.get(User, session['user_id'])
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if email != user.email and User.query.filter_by(email=email).first():
            flash('Email is already in use.', 'error')
            return render_template('profile.html', user=user, bootstrap=True)
        if username != user.username and User.query.filter_by(username=username).first():
            flash('Username is already taken.', 'error')
            return render_template('profile.html', user=user, bootstrap=True)
        if password and not is_strong_password(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, and numbers.', 'error')
            return render_template('profile.html', user=user, bootstrap=True)
        user.username = username
        user.email = email
        if password:
            user.set_password(password)
        db.session.commit()
        log = AuditLog(user_id=user.id, action=f'User {user.username} updated profile')
        db.session.add(log)
        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user, bootstrap=True)

@app.route('/admin')
@login_required
def admin():
    user = db.session.get(User, session['user_id'])

    if user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))

    if not user.two_factor_secret:
        return redirect(url_for('setup_2fa'))

    if not session.get('two_factor_authenticated'):
        return redirect(url_for('verify2fa'))

    users = User.query.all()
    logs = AuditLog.query.all()
    documents = Document.query.all()

    return render_template('admin.html', user=user, users=users, logs=logs, documents=documents, bootstrap=True)



@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    user = db.session.get(User, session['user_id'])
    if user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'user')
        if User.query.filter_by(email=email).first():
            flash('Email is already in use.', 'error')
            return render_template('add_user.html', user=user, bootstrap=True)
        if User.query.filter_by(username=username).first():
            flash('Username is already taken.', 'error')
            return render_template('add_user.html', user=user, bootstrap=True)
        if not is_strong_password(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, and numbers.', 'error')
            return render_template('add_user.html', user=user, bootstrap=True)
        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        log = AuditLog(user_id=user.id, action=f'Admin {user.username} added user: {username}')
        db.session.add(log)
        db.session.commit()
        flash('User added successfully.', 'success')
        return redirect(url_for('admin'))
    return render_template('add_user.html', user=user, bootstrap=True)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = db.session.get(User, session['user_id'])
    if user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    target_user = db.session.get(User, user_id)
    if not target_user:
        flash('User not found.', 'error')
        return redirect(url_for('admin'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'user')
        if email != target_user.email and User.query.filter_by(email=email).first():
            flash('Email is already in use.', 'error')
            return render_template('edit_user.html', user=user, target_user=target_user, bootstrap=True)
        if username != target_user.username and User.query.filter_by(username=username).first():
            flash('Username is already taken.', 'error')
            return render_template('edit_user.html', user=user, target_user=target_user, bootstrap=True)
        if password and not is_strong_password(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, and numbers.', 'error')
            return render_template('edit_user.html', user=user, target_user=target_user, bootstrap=True)
        target_user.username = username
        target_user.email = email
        target_user.role = role
        if password:
            target_user.set_password(password)
        db.session.commit()
        log = AuditLog(user_id=user.id, action=f'Admin {user.username} updated user: {username}')
        db.session.add(log)
        db.session.commit()
        flash('User updated successfully.', 'success')
        return redirect(url_for('admin'))
    return render_template('edit_user.html', user=user, target_user=target_user, bootstrap=True)

@app.route('/admin/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    user = db.session.get(User, session['user_id'])
    if user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    target_user = db.session.get(User, user_id)
    if not target_user:
        flash('User not found.', 'error')
        return redirect(url_for('admin'))
    if target_user.id == user.id:
        flash('You cannot delete yourself.', 'error')
        return redirect(url_for('admin'))
    AuditLog.query.filter_by(user_id=target_user.id).delete()
    Document.query.filter_by(user_id=target_user.id).delete()
    db.session.delete(target_user)
    log = AuditLog(user_id=user.id, action=f'Admin {user.username} deleted user: {target_user.username}')
    db.session.add(log)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/edit_document/<int:doc_id>', methods=['GET', 'POST'])
@login_required
def edit_document(doc_id):
    user = db.session.get(User, session['user_id'])
    if user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    doc = Document.query.get_or_404(doc_id)
    if request.method =='POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('No file selected.', 'error')
            return render_template('edit_document.html', user=user, doc=doc, bootstrap=True)
        if file and file.filename.lower().endswith(('.pdf', '.docx', '.txt')):
            filename = secure_filename(file.filename)
            data = file.read()
            if len(data) > 16777215:
                flash('File too large. Maximum size is 16 MB.', 'error')
                return render_template('edit_document.html', user=user, doc=doc, bootstrap=True)
            file_hash = generate_hash(data)
            hmac_value = generate_hmac(data, HMAC_KEY)
            encrypted_data = encrypt_file(data, AES_KEY)
            private_key = load_private_key(user.id)
            if not private_key:
                private_key, _ = generate_key_pair(user.id)
            signature = sign_file(data, private_key)
            doc.filename = filename
            doc.file_hash = file_hash
            doc.hmac = hmac_value
            doc.encrypted_data = encrypted_data
            doc.signature = signature
            db.session.commit()
            log = AuditLog(user_id=user.id, action=f'Admin {user.username} updated document: {filename}')
            db.session.add(log)
            db.session.commit()
            flash('Document updated successfully.', 'success')
            return redirect(url_for('admin'))
        flash('Invalid file type. Only PDF, DOCX, and TXT are allowed.', 'error')
    return render_template('edit_document.html', user=user, doc=doc, bootstrap=True)

@app.route('/admin/delete_document/<int:doc_id>')
@login_required
def delete_document(doc_id):
    user = db.session.get(User, session['user_id'])
    if user.role != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    doc = Document.query.get_or_404(doc_id)
    db.session.delete(doc)
    log = AuditLog(user_id=user.id, action=f'Admin {user.username} deleted document: {doc.filename}')
    db.session.add(log)
    db.session.commit()
    flash('Document deleted successfully.', 'success')
    return redirect(url_for('admin'))

@app.route('/logout')
@login_required
def logout():
    user_id = session.get('user_id')
    user = db.session.get(User, user_id)
    session.clear()
    if user:
        log = AuditLog(user_id=user_id, action=f'User {user.username} logged out')
        db.session.add(log)
        db.session.commit()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

# Create database tables
with app.app_context():
    db.create_all()

# Run the application
if __name__ == '__main__':
    cert_path = os.path.join(app.config['CERTS_FOLDER'], 'server.crt')
    key_path = os.path.join(app.config['CERTS_FOLDER'], 'server.key')
    if os.path.exists(cert_path) and os.path.exists(key_path):
        app.run(ssl_context=(cert_path, key_path), host='0.0.0.0', port=5000, debug=True)
    else:
        # Generate self-signed certificate if not present
        from OpenSSL import crypto
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().CN = "localhost"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')
        with open(cert_path, 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(key_path, 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        app.run(host='0.0.0.0', port=5000)

