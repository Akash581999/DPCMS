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
    db, bcrypt, Users, DataFiduciary, Purpose,
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
# Main routes (keep your existing code)
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

        session.pop('registration_data', None)
        session['id'] = user.id
        flash("Email verified successfully. Proceed to consent.", "success")
        return redirect(url_for('consent'))

    return render_template('verify_otp.html')

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
        'message': f"Login successfull, welcome back {user.full_name or user.email}!",
        'token': token,
        'user': {
            'user_id': user.user_id,
            'email': user.email,
            'full_name': user.full_name,
            'role': user.role.name if user.role else None,
            'department': user.department.name if user.department else None
        }
    }
    return jsonify(response), 200

@app.route('/logout')
@login_required
def logout():
    current_user.session_token = None
    db.session.commit()
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/api/logout', methods=['POST'])
@token_required
def api_logout(current_user):
    if not current_user.session_token:
        return jsonify({'message': 'Token not found, Please login again.'}), 400

    current_user.session_token = None
    db.session.commit()
    return jsonify({'message': 'You have been logged out successfully.'}), 200

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
        'roles': [ur.role.role_name for ur in current_user.roles]
    }), 200

@app.route('/profile')
@login_required
def profile():
    if 'user_id' not in session:
        flash('Please log in to view your profile.', 'warning')
        return redirect(url_for('login'))

    user = Users.query.get(session['user_id'])

    if not user or user.session_token != session.get('session_token'):
        flash('Invalid session. Please log in again.', 'danger')
        return redirect(url_for('login'))
    return render_template('profile.html', user=user)

@app.route('/api/profile', methods=['GET'])
@token_required
def api_profile(current_user):
    if not current_user:
        return jsonify({'message': 'User not found.'}), 404

    profile_data = {
        'user_id': current_user.user_id,
        'email': current_user.email,
        'full_name': current_user.full_name,
        'role': current_user.role.name if current_user.role else None,
        'department': current_user.department.name if current_user.department else None,
        'is_active': current_user.is_active,
        'last_login': current_user.last_login.strftime('%Y-%m-%d %H:%M:%S') if current_user.last_login else None
    }
    return jsonify({'profile': profile_data}), 200

@app.route('/editprofile', methods=['GET', 'POST'])
@login_required
def editprofile():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    user = Users.query.get(session['user_id'])
    companies = DataFiduciary.query.all()

    if request.method == 'POST':
        user.full_name = request.form.get('fullname')
        user.mobile_no = request.form.get('mobile_no')
        user.address = request.form.get('address')

        new_company_id = request.form.get('company_id')
        if new_company_id:
            company = DataFiduciary.query.get(new_company_id)
            if company:
                user.company_id = company.company_id
            else:
                flash("Selected company doesn't exist.", 'danger')
                return render_template('editprofile.html', user=user, companies=companies)

        profile_image = request.files.get('profile_image')
        if profile_image and profile_image.filename != '':
            filename = secure_filename(profile_image.filename)
            upload_path = os.path.join('static/uploads', filename)
            os.makedirs(os.path.dirname(upload_path), exist_ok=True)
            profile_image.save(upload_path)
            user.profile_image = filename

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    return render_template('editprofile.html', user=user, companies=companies)

@app.route('/api/editprofile', methods=['POST'])
@token_required
def api_edit_profile(current_user):
    data = request.get_json()
    full_name = data.get('full_name')
    mobile_no = data.get('mobile_no')
    address = data.get('address')
    company_id = data.get('company_id')

    if full_name:
        current_user.full_name = full_name
    if mobile_no:
        current_user.mobile_no = mobile_no
    if address:
        current_user.address = address
    if company_id:
        company = DataFiduciary.query.get(company_id)
        if company:
            current_user.company_id = company.company_id
        else:
            return jsonify({'message': "Selected company doesn't exist."}), 400

    db.session.commit()
    return jsonify({'message': 'Profile updated successfully!'}), 200

@app.route('/changepassword', methods=['GET', 'POST'])
@login_required
def changepassword():
    user = Users.query.get(session['user_id'])

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

# ----------------------------------------------------------------
# Consent routes
# ----------------------------------------------------------------
@app.route('/consent', methods=['GET', 'POST'])
@login_required
def consent():
    user = current_user
    existing = Consent.query.filter_by(user_id=user.id).first()

    purpose = Purpose.query.filter_by(purpose_name="User registration").first()
    fiduciary = DataFiduciary.query.filter_by(name="DPDP Consultants").first()
    if not purpose or not fiduciary:
        flash("Setup error: Missing Purpose or Fiduciary.", "danger")
        return redirect(url_for('dashboard'))

    if existing and existing.status == "granted":
        flash("Consent already given.", "info")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        consent_given = request.form.get('consent_given') == 'on'
        if not consent_given:
            flash("Please agree to proceed.", "warning")
            return redirect(url_for('consent'))

        if existing:
            existing.status = "granted"
            existing.timestamp = datetime.utcnow()
            existing.method = "checkbox"
        else:
            db.session.add(Consent(
                user_id=user.id,
                purpose_id=purpose.id,
                fiduciary_id=fiduciary.id,
                status="granted",
                method="checkbox",
                timestamp=datetime.utcnow()
            ))
        db.session.commit()
        flash("Consent recorded successfully.", "success")
        return redirect(url_for('dashboard'))

    return render_template('consent_form.html', user=user)

@app.route('/api/consent', methods=['POST'])
@token_required
def api_consent(current_user):
    data = request.get_json()
    if not data or data.get('consent_given') is not True:
        return jsonify({'status': 'error', 'message': 'Consent required.'}), 400

    purpose = Purpose.query.filter_by(purpose_name="User registration").first()
    fiduciary = DataFiduciary.query.filter_by(name="DPDP Consultants").first()
    if not purpose or not fiduciary:
        return jsonify({'status': 'error', 'message': 'Setup error.'}), 500

    existing = Consent.query.filter_by(user_id=current_user.id).first()
    if existing:
        existing.status = "granted"
        existing.timestamp = datetime.utcnow()
        existing.method = "api"
    else:
        db.session.add(Consent(
            user_id=current_user.id,
            purpose_id=purpose.id,
            fiduciary_id=fiduciary.id,
            status="granted",
            method="api",
            timestamp=datetime.utcnow()
        ))
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Consent recorded.'}), 201

# ----------------------------
# Consent Form Dynamic Renderer
# ----------------------------
from flask import Response, jsonify, request
from flask_cors import CORS  # type: ignore

CORS(app)

@app.route('/consentform/<int:form_id>.js')
def consentform_js(form_id):
    """Serve a dynamic JS script that injects a consent form."""
    form = ConsentForm.query.get(form_id)
    if not form:
        return Response("console.error('Form not found');", mimetype="application/javascript")

    js_fields = ""
    for field in form.fields:
        # Normalize name (keep consistent with API expectations)
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
  console.log("📜 Dynamic Consent Form Loaded (ID {form_id})");

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

  // Handle form submission
  form.addEventListener('submit', async function(e) {{
    e.preventDefault();
    msg.textContent = '';

    const formData = new FormData(form);
    const payload = {{}};
    formData.forEach((value, key) => {{
      // Handle checkboxes explicitly
      const input = form.querySelector(`[name="{{'{{'}}${{key}}{{'}}'}}"]`);
      if (input && input.type === 'checkbox') {{
        payload[key] = input.checked;
      }} else {{
        payload[key] = value;
      }}
    }});

    console.log("📤 Submitting payload:", payload);

    try {{
      const res = await fetch('http://127.0.0.1:5000/api/consent/test', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(payload)
      }});
      const data = await res.json();
      msg.textContent = res.ok
        ? "✅ " + data.message
        : "❌ " + (data.message || "Error submitting consent.");
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
    """Store dynamic form submissions into database (only once per user)."""
    data = request.get_json() or {}
    data = {k.lower(): v for k, v in data.items()}  # normalize keys

    fullname = data.get('fullname')
    email = data.get('email')

    if not fullname or not email:
        return jsonify({'status': 'error', 'message': 'Fullname and email are required.'}), 400

    # ✅ Check if this user already gave consent
    existing_consent = ExternalConsent.query.filter_by(email=email).first()
    if existing_consent:
        return jsonify({
            'status': 'info',
            'message': f'Consent already recorded for {fullname or email}.'
        }), 200

    # ✅ Create new consent
    new_consent = ExternalConsent(
        form_id=1,  # dynamic later
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

    print(f"[SAVED] Consent received from {fullname} ({email})")
    return jsonify({'status': 'success', 'message': f'Consent recorded for {fullname}.'}), 201

# ----------------------------------------------------------------
# Admin view all consents
# ----------------------------------------------------------------
@app.route('/showallusers')
@login_required
def showallusers():
    if session.get('user_role') != 'admin':
        abort(403)

    page = request.args.get('page', 1, type=int)  # Get page number from query param
    per_page = 10  # Number of users per page

    users = Users.query.join(Role).filter(Role.name != 'admin') \
        .order_by(Users.user_id.desc()) \
        .paginate(page=page, per_page=per_page)

    roles = Role.query.filter(Role.name != 'admin').all()
    return render_template('showallusers.html', users=users, roles=roles)

@app.route('/api/showallusers', methods=['GET'])
@token_required
def api_show_all_users(current_user):
    if current_user.role.name != 'admin':
        return jsonify({'message': 'Forbidden – Admins only'}), 403

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    # Paginate the user query
    users_pagination = Users.query.join(Role).filter(Role.name != 'admin') \
        .order_by(Users.user_id.desc()) \
        .paginate(page=page, per_page=per_page, error_out=False)

    # Get role data (all at once, not paginated)
    roles = Role.query.filter(Role.name != 'admin').all()
    role_data = [role.name for role in roles]

    user_data = []
    for user in users_pagination.items:
        user_data.append({
            'user_id': user.user_id,
            'email': user.email,
            'full_name': user.full_name,
            'role': user.role.name if user.role else None,
            'department': user.department.name if user.department else None,
            'is_active': user.is_active
        })

    return jsonify({
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
    if not any(ur.role.role_name == 'admin' for ur in current_user.roles):
        abort(403)
    consents = Consent.query.order_by(Consent.timestamp.desc()).all()
    return render_template('showallconsents.html', consents=consents)

@app.route('/api/showallconsents')
@token_required
def api_showallconsents(current_user):
    if not any(ur.role.role_name == 'admin' for ur in current_user.roles):
        return jsonify({'message': 'Admins only.'}), 403
    consents = Consent.query.order_by(Consent.timestamp.desc()).all()
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

@app.route('/showallcompanies')
@login_required
def showallcompanies():
    if session.get('user_role') != 'admin':
        abort(403)
    companies = DataFiduciary.query.order_by(DataFiduciary.company_id.desc()).all()
    return render_template('showallcompanies.html', companies=companies)

@app.route('/api/showallcompanies', methods=['GET'])
@token_required
def api_show_all_companies(current_user):
    if current_user.role.name != 'admin':
        return jsonify({'message': 'Forbidden – Admins only'}), 403

    companies = DataFiduciary.query.order_by(DataFiduciary.company_id.desc()).all()
    company_data = []
    for company in companies:
        company_data.append({
            'company_id': company.company_id,
            'name': company.name,
            'address': company.address
        })
    return jsonify({'companies': company_data}), 200

@app.route('/showallfeedbacks')
@login_required
def showallfeedbacks():
    if session.get('user_role') != 'admin':
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
        if fid and not Purpose.query.filter_by(purpose_name='User registration').first():
            db.session.add(Purpose(
                purpose_name='User registration',
                description='Default purpose for user registration',
                fiduciary_id=fid.id
            ))
            db.session.commit()
            print("✅ Default Purpose created.")
    app.run(debug=True)