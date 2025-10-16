import uuid
from flask import (
    Flask, jsonify, render_template, request, redirect,
    url_for, flash, session, abort
)
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from flask_login import (
    LoginManager, login_user, logout_user,
    current_user, login_required
)
from flask_migrate import Migrate # type: ignore
from flask_bcrypt import Bcrypt # type: ignore
from functools import wraps
import jwt, os, secrets, random # type: ignore
from dotenv import load_dotenv # type: ignore
from config import Config
from models import (
    db, bcrypt, AuditLog, CookieConsent, Grievance, GrievanceAction, MailMessage, Notification, Users, DataFiduciary, Purpose,
    Role, UserRole, Consent, Contacts, ConsentForm, ExternalConsent
)
from sendmail import send_email_with_otp

app = Flask(__name__)
load_dotenv()

# ----------------------------------------------------------------
# Flask app setup
# ----------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(Config)

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost:5432/DPCMS'
app.config['SECRET_KEY'] = "akashkumar1999"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ✅ Initialize extensions with Flask app
db.init_app(app)
bcrypt.init_app(app)
migrate = Migrate(app, db)

# ----------------------------------------------------------------
# Flask-Login setup
# ----------------------------------------------------------------
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = 'strong'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)

# ----------------------------------------------------------------
# JWT helper
# ----------------------------------------------------------------
def generate_token(user):
    payload = {
        'id': user.id,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].replace('Bearer ', '')
        elif 'jwt_token' in request.cookies:
            token = request.cookies['jwt_token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = Users.query.get(data['id'])
            if not current_user:
                raise Exception("User not found")
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired!'}), 401
        except Exception:
            return jsonify({'message': 'Token invalid!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# ----------------------------------------------------------------
# Utility helpers
# ----------------------------------------------------------------
def generate_otp(length=4):
    return ''.join(random.choice("0123456789") for _ in range(length))

def has_valid_consent(user):
    consent = Consent.query.filter_by(user_id=user.id).first()
    return consent and consent.status == "granted"

def send_notification(user_id, message, type="consent_update"):
    notif = Notification(
        user_id=user_id,
        fiduciary_id=None,
        type=type,
        message=message,
        channel="in_app",
        status="sent"
    )
    db.session.add(notif)
    db.session.commit()
# ----------------------------------------------------------------
# Ensure all tables are created
# ----------------------------------------------------------------
def create_tables_if_not_exist():
    """Creates PostgreSQL tables if they don't exist yet."""
    from models import (
        Users, DataFiduciary, Purpose, Role, UserRole,
        Consent, Contacts
    )  # ensure all models are loaded
    db.create_all()
    db.session.commit()

# ----------------------------------------------------------------
# Main routes
# ----------------------------------------------------------------
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

# ----------------------------------------------------------------
# Contact form
# ----------------------------------------------------------------
@app.route('/contacts', methods=['GET', 'POST'])
def contacts():
    if request.method == 'POST':
        fullname = request.form.get('fullname')
        email = request.form.get('email')
        mobile_no = request.form.get('mobile_no')
        address = request.form.get('address')
        message = request.form.get('message')
        rating = request.form.get('rating')

        if not all([fullname, email, mobile_no, message]):
            flash('Please fill out all required fields.', 'warning')
            return redirect(url_for('contacts'))

        try:
            rating = int(rating) if rating else None
            if rating and (rating < 1 or rating > 5):
                flash('Rating must be between 1 and 5.', 'warning')
                return redirect(url_for('contacts'))
        except ValueError:
            flash('Invalid rating value.', 'warning')
            return redirect(url_for('contacts'))

        contact = Contacts(
            fullname=fullname,
            email=email,
            mobile_no=mobile_no,
            address=address,
            message=message,
            rating=rating,
            sent_on=datetime.utcnow(),
            read_status='Unread'
        )
        db.session.add(contact)
        db.session.commit()
        flash('Your message has been sent successfully.', 'success')
        return redirect(url_for('contacts'))
    return render_template('contacts.html')

# ----------------------------------------------------------------
# Registration
# ----------------------------------------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        fullname = request.form.get('fullname')
        mobile_no = request.form.get('mobile_no')
        address = request.form.get('address')

        if Users.query.filter_by(email=email).first():
            flash("User already exists.", "danger")
            return redirect(url_for('register'))

        role = Role.query.filter_by(role_name='employee').first()
        if not role:
            flash("Default role 'employee' not found.", "danger")
            return redirect(url_for('register'))

        otp = generate_otp()
        new_user = Users(
            email=email, fullname=fullname,
            mobile_no=mobile_no, address=address,
            is_active=True
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.flush()

        db.session.add(UserRole(user_id=new_user.id, role_id=role.id))
        db.session.commit()

        try:
            send_email_with_otp(email=email, otp=otp, fullname=fullname)
            session['registration_data'] = {'id': new_user.id, 'otp': otp}
            flash("OTP sent to your email. Verify to complete registration.", "info")
            return redirect(url_for('verify_otp'))
        except Exception as e:
            flash(f"Failed to send OTP: {str(e)}", "danger")
            db.session.rollback()
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    reg_data = session.get('registration_data')
    if not reg_data:
        flash("Session expired. Please register again.", "warning")
        return redirect(url_for('register'))

    if request.method == 'POST':
        entered = request.form.get('otp')
        if entered != str(reg_data.get('otp')):
            flash("Invalid OTP.", "danger")
            return redirect(url_for('verify_otp'))

        user = Users.query.get(reg_data['id'])
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for('register'))

        # ✅ OTP verified — clear registration data
        session.pop('registration_data', None)
        session['user_id_for_consent'] = user.id  # store for consent step
        flash("Email verified successfully. Please review the consent form.", "success")
        return redirect(url_for('consent'))
    return render_template('verify_otp.html')

# ----------------------------------------------------------------
# Consent routes
# ----------------------------------------------------------------
@app.route('/consent', methods=['GET', 'POST'])
def consent():
    user_id = session.get('user_id_for_consent')
    if not user_id:
        flash("Session expired. Please verify again.", "warning")
        return redirect(url_for('register'))

    user = Users.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('register'))

    purpose = Purpose.query.filter_by(purpose_name="User registration").first()
    fiduciary = DataFiduciary.query.filter_by(name="DPDP Consultants").first()
    if not purpose or not fiduciary:
        flash("Setup error: Missing Purpose or Fiduciary.", "danger")
        return redirect(url_for('register'))

    existing = Consent.query.filter_by(user_id=user.id).first()
    if existing and existing.status == "granted":
        flash("Consent already given. You can now log in.", "info")
        return redirect(url_for('login'))

    if request.method == 'POST':
        consent_given = request.form.get('consent_given') == 'on'
        if not consent_given:
            flash("You must agree to proceed.", "warning")
            return redirect(url_for('consent'))

        # ✅ Create or update consent
        if existing:
            existing.status = "granted"
            existing.timestamp = datetime.utcnow()
            existing.method = "checkbox"
        else:
            new_consent = Consent(
                user_id=user.id,
                purpose_id=purpose.id,
                fiduciary_id=fiduciary.id,
                status="granted",
                method="checkbox",
                timestamp=datetime.utcnow()
            )
            db.session.add(new_consent)
        db.session.commit()

        # ✅ Redirect to login after successful consent
        session.pop('user_id_for_consent', None)
        flash("Consent recorded successfully. You may now log in.", "success")
        return redirect(url_for('login'))
    return render_template('consent_form.html', user=user)

@app.route('/api/consent', methods=['POST'])
@token_required
def api_consent(current_user):
    """Collect and record user consent via API (only once per user per purpose)."""
    data = request.get_json() or {}

    consent_given = data.get('consent_given')
    method = data.get('method', 'api')

    if consent_given not in [True, 'true', 'True', 1, '1']:
        return jsonify({'status': 'error', 'message': 'Consent not provided.'}), 400

    # Fetch purpose and fiduciary dynamically
    purpose = Purpose.query.filter_by(purpose_name="User registration").first()
    fiduciary = DataFiduciary.query.filter_by(name="DPDP Consultants").first()

    if not purpose or not fiduciary:
        return jsonify({
            'status': 'error',
            'message': 'System setup error — missing Purpose or Fiduciary.'
        }), 500

    # ✅ Check if this user already gave consent for this purpose
    existing = Consent.query.filter_by(
        user_id=current_user.id,
        purpose_id=purpose.id
    ).first()

    if existing and existing.status == "granted":
        return jsonify({
            'status': 'info',
            'message': 'Consent already recorded for this purpose.'
        }), 200

    # ✅ Create or update consent
    if existing:
        existing.status = "granted"
        existing.method = method
        existing.timestamp = datetime.utcnow()
    else:
        new_consent = Consent(
            user_id=current_user.id,
            purpose_id=purpose.id,
            fiduciary_id=fiduciary.id,
            status="granted",
            method=method,
            timestamp=datetime.utcnow(),
            expiry_date=None,
            language=data.get('language')
        )
        db.session.add(new_consent)

    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': f'Consent successfully recorded for user {current_user.fullname}.'
    }), 201

# ----------------------------------------------------------------
# Login / Logout
# ----------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'

        user = Users.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash("Invalid credentials.", "danger")
            return render_template('login.html')

        if not user.is_active:
            flash("Account blocked. Contact admin.", "danger")
            return render_template('login.html')

        token = generate_token(user)
        session_token = secrets.token_urlsafe(32)
        user.session_token = session_token
        user.last_login = datetime.utcnow()
        db.session.commit()

        login_user(user, remember=remember)
        session['jwt_token'] = token
        print(token)

        if not has_valid_consent(user):
            flash("Consent required to continue.", "info")
            return redirect(url_for('consent'))

        flash(f"Welcome {user.fullname}!", "success")
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()

    if not data:
        return jsonify({'message': 'No input data provided'}), 400

    email = data.get('email', '').strip().lower()
    password = data.get('password')
    remember = data.get('remember', False)

    if not email or not password:
        return jsonify({'message': 'Email and password are required.'}), 400

    user = Users.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid email or password.'}), 401

    if not user.is_active:
        return jsonify({
            'message': 'Your account is blocked. Please contact admin (akash581999@gmail.com).'
        }), 403

    token = generate_token(user)
    print(token)
    session_token = secrets.token_urlsafe(32)

    user.session_token = session_token
    user.last_login = datetime.utcnow()
    db.session.commit()

    response = {
        'message': f"Login successful, welcome back {user.fullname or user.email}!",
        'user': {
            'user_id': user.id,
            'email': user.email,
            'fullname': user.fullname,
            'roles': [ur.role.role_name for ur in user.roles] if user.roles else [],
            'jwt_token': token,
            'session_token': session_token
        }
    }
    return jsonify(response), 200

@app.route('/logout')
@login_required
def logout():
    current_user.session_token = None
    db.session.commit()
    logout_user()
    flash("You have been successfully logged out.", "info")
    return redirect(url_for('login'))

@app.route('/api/logout', methods=['POST'])
@token_required
def api_logout(current_user):
    if not current_user.session_token:
        return jsonify({'message': 'Token not found, Please login again.'}), 400

    current_user.session_token = None
    db.session.commit()
    return jsonify({'message': 'You have successfully been logged out.'}), 200

@app.route('/resetpassword', methods=['GET', 'POST'])
def resetpassword():
    if request.method == 'POST':
        email = request.form.get('email')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        user = Users.query.filter_by(email=email).first()

        if not user:
            flash('Email not found.', 'danger')
            return redirect(url_for('resetpassword'))

        if new_password != confirm_password:
            flash('Passwords do not match.', 'warning')
            return redirect(url_for('resetpassword'))

        user.set_password(new_password)
        db.session.commit()

        flash('Password has been reset successfully. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('resetpassword.html')

@app.route('/api/resetpassword', methods=['POST'])
def api_reset_password():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    if not email or not new_password or not confirm_password:
        return jsonify({'message': 'All fields are required.'}), 400

    user = Users.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Email not found.'}), 404

    if new_password != confirm_password:
        return jsonify({'message': 'Passwords do not match.'}), 400

    user.set_password(new_password)
    db.session.commit()
    return jsonify({'message': 'Password has been reset successfully. Please login.'}), 200

# ----------------------------------------------------------------
# Dashboard
# ----------------------------------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    if not has_valid_consent(current_user):
        flash("Consent missing or expired.", "warning")
        return redirect(url_for('consent'))
    return render_template('dashboard.html', user=current_user)

@app.route('/api/dashboard', methods=['GET'])
@token_required
def api_dashboard(current_user):
    if not has_valid_consent(current_user):
        return jsonify({
            'message': 'Consent required',
            'consent_required': True
        }), 403

    return jsonify({
        'message': f"Welcome {current_user.fullname}",
        'email': current_user.email,
        'roles': [ur.role.role_name for ur in current_user.roles] if current_user.roles else []
    }), 200

@app.route('/profile')
@login_required
def profile():
    user = current_user

    if not user.is_authenticated:
        flash('Please log in to view your profile.', 'warning')
        return redirect(url_for('login'))

    company = DataFiduciary.query.filter_by(dpo_id=user.id).first()
    return render_template('profile.html', user=user, company=company)

@app.route('/api/profile', methods=['GET'])
@token_required
def api_profile(current_user):
    if not current_user:
        return jsonify({'message': 'User not found.'}), 404

    profile_data = {
        'user_id': current_user.id,
        'email': current_user.email,
        'fullname': current_user.fullname,
        'roles': [ur.role.role_name for ur in current_user.roles] if current_user.roles else [],
        'is_active': current_user.is_active,
        'last_login': current_user.last_login.strftime('%Y-%m-%d %H:%M:%S') if current_user.last_login else None
    }
    return jsonify({'profile': profile_data}), 200

@app.route('/changepassword', methods=['GET', 'POST'])
@login_required
def changepassword():
    user = current_user

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not user.check_password(current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('changepassword'))

        if new_password != confirm_password:
            flash('New passwords do not match.', 'warning')
            return redirect(url_for('changepassword'))

        user.set_password(new_password)
        db.session.commit()
        flash('Password updated successfully.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('changepassword.html')

@app.route('/api/changepassword', methods=['POST'])
@token_required
def api_change_password(current_user):
    data = request.get_json()

    if not data:
        return jsonify({'message': 'No data provided.'}), 400

    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    if not current_password or not new_password or not confirm_password:
        return jsonify({'message': 'All fields are required.'}), 400

    if not current_user.check_password(current_password):
        return jsonify({'message': 'Current password is incorrect.'}), 401

    if new_password != confirm_password:
        return jsonify({'message': 'New passwords do not match.'}), 400

    current_user.set_password(new_password)
    db.session.commit()
    return jsonify({'message': 'Password updated successfully.'}), 200

# -----------------------------------
# External consent from dynamic forms in html template.
# -----------------------------------
from flask import Response, jsonify, request
from flask_cors import CORS  # type: ignore

CORS(app)

@app.route('/consentform/<int:form_id>.js')
def consentform_js(form_id):
    form = ConsentForm.query.get(form_id)
    if not form:
        return Response("console.error('Form not found');", mimetype="application/javascript")

    js_fields = ""
    for field in form.fields:
        field_name = field.label.lower().replace(" ", "")
        required_flag = "input.required = true;" if field.required else ""

        if field.field_type == "select":
            options_js = ""
            if field.options:
                for opt in [o.strip() for o in field.options.split(",") if o.strip()]:
                    options_js += f"""
                    var option = document.createElement('option');
                    option.value = '{opt}';
                    option.textContent = '{opt}';
                    select.appendChild(option);
                    """
            js_fields += f"""
            var label = document.createElement('label');
            label.textContent = '{field.label}: ';
            var select = document.createElement('select');
            select.name = '{field_name}';
            {'select.required = true;' if field.required else ''}
            {options_js}
            form.appendChild(label);
            form.appendChild(select);
            form.appendChild(document.createElement('br'));
            """

        elif field.field_type == "checkbox":
            js_fields += f"""
            var checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.name = '{field_name}';
            {'checkbox.required = true;' if field.required else ''}
            form.appendChild(checkbox);
            form.appendChild(document.createTextNode(' {field.label}'));
            form.appendChild(document.createElement('br'));
            """

        else:  # text, email, number, etc.
            js_fields += f"""
            var label = document.createElement('label');
            label.textContent = '{field.label}: ';
            var input = document.createElement('input');
            input.type = '{field.field_type}';
            input.name = '{field_name}';
            {required_flag}
            form.appendChild(label);
            form.appendChild(input);
            form.appendChild(document.createElement('br'));
            """

    # Build the JS to render + submit the form
    js = f"""
(function() {{
  console.log("📜 Dynamic Consent Form (ID {form_id}) Loaded");
  var container = document.getElementById('consent-form') || document.body;
  var form = document.createElement('form');
  form.id = 'dynamicConsentForm';

  {js_fields}

  var button = document.createElement('button');
  button.textContent = 'Submit';
  button.type = 'submit';
  form.appendChild(button);

  var msg = document.createElement('div');
  msg.style.marginTop = '10px';
  form.appendChild(msg);

  form.addEventListener('submit', async function(e) {{
    e.preventDefault();
    msg.textContent = '';

    const formData = new FormData(form);
    const payload = {{ form_id: {form_id} }};  // ✅ include form_id
    formData.forEach((value, key) => {{
      payload[key.toLowerCase()] = value;
    }});

    console.log("📤 Submitting payload:", payload);

    try {{
      const res = await fetch('http://127.0.0.1:5000/api/consent/test', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(payload)
      }});

      const data = await res.json();
      if (res.ok) {{
        msg.textContent = "✅ " + data.message;
      }} else {{
        msg.textContent = "❌ " + (data.message || 'Error submitting consent.');
      }}
    }} catch (err) {{
      console.error(err);
      msg.textContent = "⚠️ Network error — check Flask server.";
    }}
  }});

  container.appendChild(form);
}})();
"""
    return Response(js, mimetype="application/javascript")


@app.route('/api/consent/test', methods=['POST'])
def api_consent_test():
    """Store dynamic form submissions into database (only once per user per form)."""
    data = request.get_json() or {}
    data = {k.lower(): v for k, v in data.items()}  # normalize keys

    fullname = data.get('fullname')
    email = data.get('email')
    form_id = data.get('form_id')  # ✅ get form_id from payload

    if not fullname or not email:
        return jsonify({'status': 'error', 'message': 'Fullname and email are required.'}), 400
    if not form_id:
        return jsonify({'status': 'error', 'message': 'Form ID missing.'}), 400

    # ✅ Ensure the form exists
    form = ConsentForm.query.get(form_id)
    if not form:
        return jsonify({'status': 'error', 'message': 'Invalid form ID.'}), 404

    # ✅ Prevent duplicate consent for same form + email
    existing_consent = ExternalConsent.query.filter_by(email=email, form_id=form_id).first()
    if existing_consent:
        return jsonify({
            'status': 'info',
            'message': f'Consent already recorded for {fullname or email} on form {form_id}.'
        }), 200

    # ✅ Create new consent
    new_consent = ExternalConsent(
        form_id=form_id,
        fullname=fullname,
        email=email,
        phone=data.get('phone'),
        language=data.get('language'),
        consent_given=True,
        data_payload=data,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )

    db.session.add(new_consent)
    db.session.commit()

    print(f"[SAVED] Consent received from {fullname} ({email}) for form {form_id}")
    return jsonify({'status': 'success', 'message': f'Consent recorded for {fullname} (Form ID: {form_id}).'}), 201

# ----------------------------------------------------------------
# Admin panel view controls
# ----------------------------------------------------------------
@app.route('/showallusers')
@login_required
def showallusers():
    user = current_user

    # Save user role in session
    session['user_role'] = [ur.role.role_name for ur in user.roles][0] if user.roles else 'employee'
    if session['user_role'] != 'admin':
        abort(403)

    page = request.args.get('page', 1, type=int)
    per_page = 10

    # 🧠 Updated query: Use Users directly and exclude admin roles properly
    users_query = Users.query.join(UserRole).join(Role).filter(Role.role_name != 'admin')
    users = users_query.order_by(Users.id.desc()).paginate(page=page, per_page=per_page, error_out=False)

    roles = Role.query.filter(Role.role_name != 'admin').all()
    return render_template('showallusers.html', users=users, roles=roles)

@app.route('/api/showallusers', methods=['GET'])
@token_required
def api_show_all_users(current_user):
    # Ensure current_user is admin
    if not any(ur.role.role_name == 'admin' for ur in current_user.roles):
        return jsonify({'message': 'Forbidden – Admins only'}), 403

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    # 🧠 Query all non-admin users
    users_query = Users.query.join(UserRole).join(Role).filter(Role.role_name != 'admin')
    users_pagination = users_query.order_by(Users.id.desc()).paginate(page=page, per_page=per_page, error_out=False)

    # 🧠 Get all available roles except admin
    roles = Role.query.filter(Role.role_name != 'admin').all()
    role_data = [role.role_name for role in roles]

    # 🧠 Format user data for API response
    user_data = []
    for user in users_pagination.items:
        user_data.append({
            'id': user.id,
            'fullname': user.fullname,
            'email': user.email,
            'mobile_no': user.mobile_no,
            'roles': [ur.role.role_name for ur in user.roles] if user.roles else [],
            'is_active': user.is_active,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S') if hasattr(user, 'created_at') and user.created_at else None
        })

    return jsonify({
        'status': 'success',
        'users': user_data,
        'roles': role_data,
        'pagination': {
            'total_items': users_pagination.total,
            'total_pages': users_pagination.pages,
            'current_page': users_pagination.page,
            'per_page': users_pagination.per_page,
            'has_next': users_pagination.has_next,
            'has_prev': users_pagination.has_prev
        }
    }), 200

@app.route('/showallconsents')
@login_required
def showallconsents():
    # ✅ Only admins can access
    if not any(ur.role.role_name == 'admin' for ur in current_user.roles):
        abort(403)

    # ✅ Exclude consents belonging to admin users
    consents = (
        Consent.query
        .join(Users, Consent.user_id == Users.id)
        .filter(~Users.roles.any(UserRole.role.has(Role.role_name == 'admin')))
        .order_by(Consent.timestamp.desc())
        .all()
    )
    return render_template('showallconsents.html', consents=consents)

@app.route('/api/showallconsents')
@token_required
def api_showallconsents(current_user):
    # ✅ Only admins can access
    if not any(ur.role.role_name == 'admin' for ur in current_user.roles):
        return jsonify({'message': 'Admins only.'}), 403

    # ✅ Exclude consents belonging to admin users
    consents = (
        Consent.query
        .join(Users, Consent.user_id == Users.id)
        .filter(~Users.roles.any(UserRole.role.has(Role.role_name == 'admin')))
        .order_by(Consent.timestamp.desc())
        .all()
    )

    return jsonify({
        'status': 'success',
        'consents': [
            {
                'id': c.id,
                'user_id': c.user_id,
                'status': c.status,
                'timestamp': c.timestamp.isoformat() if c.timestamp else None
            } for c in consents
        ]
    }), 200

@app.route('/showallfeedbacks')
@login_required
def showallfeedbacks():
    user=current_user
    session['user_role'] = [ur.role.role_name for ur in user.roles][0] if user.roles else 'employee'
    if session['user_role'] != 'admin':
        abort(403)
    page = request.args.get('page', 1, type=int)
    per_page = 10

    pagination = Contacts.query.order_by(Contacts.id.desc()).paginate(page=page, per_page=per_page)
    contacts = pagination.items

    return render_template('showallfeedbacks.html', contacts=contacts, pagination=pagination)

@app.route('/api/showallfeedbacks', methods=['GET'])
@token_required
def api_show_all_feedbacks(current_user):
    if not current_user.role or current_user.role.name.lower() != 'admin':
        return jsonify({'message': 'Forbidden – Admins only'}), 403

    # Get page and per_page from query parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    # Paginate query
    pagination = Contacts.query.order_by(Contacts.id.desc()).paginate(page=page, per_page=per_page)
    contacts = pagination.items

    # Build contact data
    contact_data = [
        {
            'id': contact.id,
            'fullname': contact.fullname,
            'email': contact.email,
            'mobile_no': contact.mobile_no,
            'address': contact.address,
            'message': contact.message,
            'rating': contact.rating,
            'sent_on': contact.sent_on.strftime('%Y-%m-%d %H:%M:%S') if contact.sent_on else None,
            'read_status': contact.read_status.name if contact.read_status else None
        }
        for contact in contacts
    ]

    # Return paginated response with metadata
    return jsonify({
        'contacts': contact_data,
        'pagination': {
            'current_page': pagination.page,
            'per_page': pagination.per_page,
            'total_pages': pagination.pages,
            'total_items': pagination.total,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev,
            'next_page': pagination.next_num,
            'prev_page': pagination.prev_num
        }
    }), 200

from sqlalchemy.exc import IntegrityError

# ---------------------------------------------------------------------
# 1️⃣ ROLE MANAGEMENT (Admin - Web Interface)
# ---------------------------------------------------------------------
@app.route('/admin/roles', methods=['GET', 'POST'])
@login_required
def admin_roles():
    user = current_user
    roles = Role.query.order_by(Role.created_at.desc()).all()
    if not user or user.primary_role != 'admin':
        abort(403)

    if request.method == 'POST':
        role_name = request.form.get('role_name', '').strip()
        description = request.form.get('description', '').strip()

        if not role_name:
            flash('Role name is required.', 'warning')
            return redirect(url_for('admin_roles'))

        existing_role = Role.query.filter(db.func.lower(Role.role_name) == role_name.lower()).first()
        if existing_role:
            flash('Role name already exists.', 'danger')
            return redirect(url_for('admin_roles'))

        try:
            new_role = Role(role_name=role_name, description=description)
            db.session.add(new_role)
            db.session.commit()
            flash(f'Role "{role_name}" created successfully.', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('Database integrity error while creating role.', 'danger')

        return redirect(url_for('admin_roles'))
    return render_template('roles.html', roles=roles, user=user)

@app.route('/admin/roles/delete/<string:id>', methods=['POST'])
@login_required
def delete_role(id):
    if not current_user or current_user.primary_role != 'admin':
        abort(403)

    role = Role.query.get_or_404(id)

    assigned_users = UserRole.query.filter_by(role_id=role.id).count()
    if assigned_users > 0:
        flash('Cannot delete a role that is currently assigned to users.', 'warning')
        return redirect(url_for('admin_roles'))

    db.session.delete(role)
    db.session.commit()
    flash(f'Role "{role.role_name}" deleted successfully.', 'success')
    return redirect(url_for('admin_roles'))

@app.route('/api/admin/roles', methods=['GET', 'POST'])
@login_required
def api_admin_roles():
    if not current_user or current_user.primary_role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        role_name = data.get('role_name', '').strip()
        description = data.get('description', '').strip()

        if not role_name:
            return jsonify({'error': 'Role name is required.'}), 400

        existing_role = Role.query.filter(db.func.lower(Role.role_name) == role_name.lower()).first()
        if existing_role:
            return jsonify({'error': 'Role already exists.'}), 409

        try:
            new_role = Role(role_name=role_name, description=description)
            db.session.add(new_role)
            db.session.commit()
            return jsonify({
                'message': 'Role created successfully.',
                'role': {
                    'id': new_role.id,
                    'role_name': new_role.role_name,
                    'description': new_role.description,
                    'created_at': new_role.created_at
                }
            }), 201
        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'Database integrity error.'}), 500

    roles = Role.query.order_by(Role.created_at.desc()).all()
    return jsonify([{
        'id': role.id,
        'role_name': role.role_name,
        'description': role.description,
        'created_at': role.created_at
    } for role in roles]), 200

@app.route('/api/admin/roles/<string:id>', methods=['DELETE'])
@login_required
def api_delete_role(id):
    if not current_user or current_user.primary_role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    role = Role.query.get_or_404(id)
    assigned_users = UserRole.query.filter_by(role_id=role.id).count()
    if assigned_users > 0:
        return jsonify({'error': 'Cannot delete a role assigned to users.'}), 400

    db.session.delete(role)
    db.session.commit()
    return jsonify({'message': f'Role "{role.role_name}" deleted successfully.'}), 200

# ----------------------------
# 2️⃣ DATA FIDUCIARIES MANAGEMENT
# ----------------------------
@app.route('/admin/fiduciaries', methods=['GET', 'POST'])
@login_required
def admin_fiduciaries():
    user = current_user
    if current_user.primary_role != 'admin':
        abort(403)

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('contact_email')

        if not all([name, email]):
            flash('Both name and contact email are required.', 'warning')
            return redirect(url_for('admin_fiduciaries'))

        db.session.add(DataFiduciary(name=name.strip(), contact_email=email.strip()))
        db.session.commit()
        flash('Data Fiduciary added successfully.', 'success')
        return redirect(url_for('admin_fiduciaries'))

    fiduciaries = DataFiduciary.query.order_by(DataFiduciary.created_at.desc()).all()
    return render_template('fiduciaries.html', fiduciaries=fiduciaries, user=user)

@app.route('/admin/fiduciaries/delete/<string:id>', methods=['POST'])
@login_required
def delete_fiduciary(id):
    if current_user.primary_role != 'admin':
        abort(403)

    fid = DataFiduciary.query.get_or_404(id)
    db.session.delete(fid)
    db.session.commit()
    flash('Data Fiduciary deleted successfully.', 'success')
    return redirect(url_for('admin_fiduciaries'))

# ----------------------------
# 3️⃣ PURPOSE MANAGEMENT
# ----------------------------
@app.route('/admin/purposes', methods=['GET', 'POST'])
@login_required
def admin_purposes():
    user = current_user
    if current_user.primary_role != 'admin':
        abort(403)

    if request.method == 'POST':
        purpose_name = request.form.get('purpose_name')
        description = request.form.get('description')
        fid_id = request.form.get('fiduciary_id')

        if not all([purpose_name, fid_id]):
            flash('Purpose name and fiduciary are required.', 'warning')
            return redirect(url_for('admin_purposes'))

        db.session.add(Purpose(
            purpose_name=purpose_name.strip(),
            description=description,
            fiduciary_id=fid_id
        ))
        db.session.commit()
        flash('Purpose created successfully.', 'success')
        return redirect(url_for('admin_purposes'))

    purposes = Purpose.query.order_by(Purpose.created_at.desc()).all()
    fiduciaries = DataFiduciary.query.all()
    return render_template('purposes.html', purposes=purposes, fiduciaries=fiduciaries, user=user)

@app.route('/admin/purposes/delete/<string:id>', methods=['POST'])
@login_required
def delete_purpose(id):
    if current_user.primary_role != 'admin':
        abort(403)

    purpose = Purpose.query.get_or_404(id)
    db.session.delete(purpose)
    db.session.commit()
    flash('Purpose deleted successfully.', 'success')
    return redirect(url_for('admin_purposes'))


# ----------------------------
# 4️⃣ MAIL TEMPLATE MANAGEMENT
# ----------------------------
@app.route('/admin/mailtemplates', methods=['GET', 'POST'])
@login_required
def admin_mailtemplates():
    user = current_user
    if current_user.primary_role != 'admin':
        abort(403)

    if request.method == 'POST':
        template_type = request.form.get('template_type')
        subject = request.form.get('subject')
        body = request.form.get('body')
        link_url = request.form.get('link_url')

        if not all([template_type, subject, body]):
            flash('Template type, subject, and body are required.', 'warning')
            return redirect(url_for('admin_mailtemplates'))

        existing = MailMessage.query.filter_by(template_type=template_type).first()
        if existing:
            existing.subject = subject
            existing.body = body
            existing.link_url = link_url
            existing.updated_at = datetime.utcnow()
            flash('Template updated successfully.', 'info')
        else:
            db.session.add(MailMessage(
                template_type=template_type,
                subject=subject,
                body=body,
                link_url=link_url
            ))
            flash('New template added.', 'success')

        db.session.commit()
        return redirect(url_for('admin_mailtemplates'))

    templates = MailMessage.query.order_by(MailMessage.updated_at.desc()).all()
    return render_template('mailtemplates.html', templates=templates, user=user)

@app.route('/admin/mailtemplates/delete/<int:id>', methods=['POST'])
@login_required
def delete_mailtemplate(id):
    if current_user.primary_role != 'admin':
        abort(403)

    template = MailMessage.query.get_or_404(id)
    db.session.delete(template)
    db.session.commit()
    flash('Mail template deleted.', 'success')
    return redirect(url_for('admin_mailtemplates'))

# ----------------------------------------------------------------
# Consent Lifecycle Management
# ----------------------------------------------------------------
from sendmail import send_notification

@app.before_request
def check_user_consent():
    if current_user.is_authenticated:
        consent = Consent.query.filter_by(user_id=current_user.id).first()
        # If consent is withdrawn, redirect to consent form
        if consent and consent.status == 'withdrawn':
            if request.endpoint not in ('renew_consent', 'consent_status', 'logout', 'static'):
                return redirect(url_for('consent_status'))

@app.route('/consent/status')
@login_required
def consent_status():
    consent = Consent.query.filter_by(user_id=current_user.id).first()
    return render_template('consent_status.html', user=current_user, consent=consent)

@app.route('/consent/withdraw', methods=['POST'])
@login_required
def withdraw_consent():
    consent = Consent.query.filter_by(user_id=current_user.id).first()
    if not consent or consent.status != 'granted':
        flash('No active consent to withdraw.', 'warning')
        return redirect(url_for('dashboard'))

    consent.status = 'withdrawn'
    consent.timestamp = datetime.utcnow()
    db.session.commit()

    # ✅ Notify user
    send_notification(
        current_user.id,
        message="Your consent has been successfully withdrawn.",
        type="consent_update",
        subject="Consent Withdrawn Confirmation"
    )

    flash('Your consent has been withdrawn successfully.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/consent/renew', methods=['POST'])
@login_required
def renew_consent():
    consent = Consent.query.filter_by(user_id=current_user.id).first()
    if not consent:
        flash('No consent record found to renew.', 'danger')
        return redirect(url_for('dashboard'))

    consent.status = 'granted'
    consent.timestamp = datetime.utcnow()
    consent.expiry_date = datetime.utcnow() + timedelta(days=365)
    db.session.commit()

    # ✅ Notify user
    send_notification(
        current_user.id,
        message="Your consent has been renewed successfully for another year.",
        type="consent_update",
        subject="Consent Renewal Successful"
    )

    flash('Consent renewed successfully for another year.', 'success')
    return redirect(url_for('dashboard'))


# ----------------------------------------------------------------
# Grievance Management (User + Admin)
# ----------------------------------------------------------------
@app.route('/grievance', methods=['GET', 'POST'])
@login_required
def grievance():
    if request.method == 'POST':
        category = request.form.get('category')
        description = request.form.get('description')
        ref_no = f"GRV-{uuid.uuid4().hex[:8].upper()}"

        grievance = Grievance(
            user_id=current_user.id,
            category=category,
            description=description,
            reference_number=ref_no
        )
        db.session.add(grievance)
        db.session.commit()

        # ✅ Notify the user
        send_notification(
            current_user.id,
            message=f"Your grievance has been submitted successfully. Reference Number: {ref_no}",
            type="grievance_update",
            subject="Grievance Submitted"
        )

        # ✅ Notify all admins
        admin_users = Users.query.join(UserRole).join(Role).filter(Role.role_name == 'admin').all()
        for admin in admin_users:
            send_notification(
                admin.id,
                message=(
                    f"A new grievance has been submitted by {current_user.fullname} "
                    f"(User ID: {current_user.id})\n\n"
                    f"Reference: {ref_no}\nCategory: {category}\n\nDescription:\n{description}"
                ),
                type="grievance_alert",
                subject="New Grievance Submitted"
            )

        flash(f"Grievance submitted successfully. Reference: {ref_no}", "success")
        return redirect(url_for('dashboard'))

    return render_template('grievance_form.html')

@app.route('/api/grievances', methods=['POST'])
@token_required
def api_create_grievance():
    data = request.get_json()
    category = data.get('category')
    description = data.get('description')

    if not category or not description:
        return jsonify({"error": "Both 'category' and 'description' are required."}), 400

    ref_no = f"GRV-{uuid.uuid4().hex[:8].upper()}"

    grievance = Grievance(
        user_id=current_user.id,
        category=category,
        description=description,
        reference_number=ref_no,
        status="pending",
        created_at=datetime.utcnow()
    )
    db.session.add(grievance)
    db.session.commit()

    # ✅ Notify the user
    send_notification(
        current_user.id,
        message=f"Your grievance has been submitted successfully. Reference Number: {ref_no}",
        type="grievance_update",
        subject="Grievance Submitted"
    )

    # ✅ Notify all admins
    admin_users = Users.query.join(UserRole).join(Role).filter(Role.role_name == 'admin').all()
    for admin in admin_users:
        send_notification(
            admin.id,
            message=(
                f"A new grievance has been submitted by {current_user.fullname} "
                f"(User ID: {current_user.id})\n\n"
                f"Reference: {ref_no}\nCategory: {category}\n\nDescription:\n{description}"
            ),
            type="grievance_alert",
            subject="New Grievance Submitted"
        )

    return jsonify({
        "message": "Grievance submitted successfully.",
        "reference_number": ref_no,
        "category": category,
        "description": description
    }), 201

@app.route('/admin/grievances')
@login_required
def admin_grievances():
    if not any(ur.role.role_name == 'admin' for ur in current_user.roles):
        abort(403)
    grievances = Grievance.query.order_by(Grievance.created_at.desc()).all()
    return render_template('admin_grievances.html', grievances=grievances)

@app.route('/api/admin/grievances', methods=['GET'])
@token_required
def api_admin_grievances():
    """API: Get all grievances (admin only)."""
    # Ensure only admin can access
    if not any(ur.role.role_name == 'admin' for ur in current_user.roles):
        return jsonify({"error": "Access denied. Admins only."}), 403

    grievances = Grievance.query.order_by(Grievance.created_at.desc()).all()

    grievances_list = [
        {
            "id": g.id,
            "reference_number": g.reference_number,
            "user_id": g.user_id,
            "user_name": g.user.fullname if g.user else None,
            "category": g.category,
            "description": g.description,
            "status": g.status,
            "created_at": g.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for g in grievances
    ]

    return jsonify({
        "total": len(grievances_list),
        "grievances": grievances_list
    }), 200

@app.route('/admin/grievances/<string:id>/resolve', methods=['POST'])
@login_required
def resolve_grievance(id):
    if not any(ur.role.role_name == 'admin' for ur in current_user.roles):
        abort(403)

    grievance = Grievance.query.get_or_404(id)
    grievance.status = 'resolved'
    db.session.add(GrievanceAction(
        grievance_id=id,
        action_taken_by=current_user.id,
        description='Resolved by admin'
    ))
    db.session.commit()

    # ✅ Notify user about resolution
    send_notification(
        grievance.user_id,
        message=f"Your grievance (Ref: {grievance.reference_number}) has been resolved by the admin.",
        type="grievance_update",
        subject="Grievance Resolved"
    )

    flash('Grievance marked as resolved.', 'success')
    return redirect(url_for('admin_grievances'))

@app.route('/api/admin/grievances/<string:id>/resolve', methods=['PATCH'])
@token_required
def api_resolve_grievance(id):
    """API: Resolve a grievance (admin only)."""
    # Only admin can resolve grievances
    if not any(ur.role.role_name == 'admin' for ur in current_user.roles):
        return jsonify({"error": "Access denied. Admins only."}), 403

    grievance = Grievance.query.get_or_404(id)

    if grievance.status == 'resolved':
        return jsonify({"message": "Grievance already resolved."}), 200

    grievance.status = 'resolved'
    db.session.add(GrievanceAction(
        grievance_id=id,
        action_taken_by=current_user.id,
        description='Resolved by admin via API'
    ))
    db.session.commit()

    # ✅ Notify the user
    send_notification(
        grievance.user_id,
        message=f"Your grievance (Ref: {grievance.reference_number}) has been resolved by the admin.",
        type="grievance_update",
        subject="Grievance Resolved"
    )

    return jsonify({
        "message": "Grievance marked as resolved successfully.",
        "grievance_id": grievance.id,
        "reference_number": grievance.reference_number,
        "status": grievance.status
    }), 200

# ----------------------------------------------------------------
# Cookie Consent APIs
# ----------------------------------------------------------------
@app.route('/api/cookies', methods=['POST'])
@token_required
def api_set_cookie_consent(current_user):
    data = request.get_json()
    category = data.get('category')
    status = data.get('status', 'granted')

    existing = CookieConsent.query.filter_by(user_id=current_user.id, category=category).first()
    if existing:
        existing.status = status
        existing.timestamp = datetime.utcnow()
    else:
        db.session.add(CookieConsent(
            user_id=current_user.id,
            category=category,
            status=status,
            timestamp=datetime.utcnow()
        ))
    db.session.commit()
    return jsonify({'message': 'Cookie consent updated.'}), 200

# ----------------------------------------------------------------
# Admin Reporting / Audit Logs
# ----------------------------------------------------------------
@app.route('/admin/auditlogs')
@login_required
def view_audit_logs():
    if not any(ur.role.role_name == 'admin' for ur in current_user.roles):
        abort(403)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template('audit_logs.html', logs=logs)

# ----------------------------------------------------------------
# External Consent Viewing (Admin)
# ----------------------------------------------------------------
@app.route('/admin/externalconsents')
@login_required
def view_external_consents():
    if not any(ur.role.role_name == 'admin' for ur in current_user.roles):
        abort(403)
    consents = ExternalConsent.query.order_by(ExternalConsent.submitted_at.desc()).all()
    return render_template('external_consents.html', consents=consents)

# ----------------------------------------------------------------
# Run app
# ----------------------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # --- Seed default data if missing ---
        if not Role.query.filter_by(role_name='employee').first():
            db.session.add(Role(role_name='employee', description='Default employee role'))
            db.session.commit()
            print("✅ Default role 'employee' created.")

        if not DataFiduciary.query.filter_by(name='DPDP Consultants').first():
            db.session.add(DataFiduciary(name='DPDP Consultants', contact_email='contact@dpdp.com'))
            db.session.commit()
            print("✅ Default Data Fiduciary created.")

        fid = DataFiduciary.query.filter_by(name='DPDP Consultants').first()
        if fid and not Purpose.query.filter_by(purpose_name='New user registration').first():
            db.session.add(Purpose(
                purpose_name='New user registration',
                description='Default purpose for new user registration',
                fiduciary_id=fid.id
            ))
            db.session.commit()
            print("✅ Default Purpose created.")
    app.run(debug=True)