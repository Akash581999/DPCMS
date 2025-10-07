from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt # type: ignore
from flask_login import UserMixin
from datetime import datetime
import uuid
import enum

db = SQLAlchemy()
bcrypt = Bcrypt()

# ---------------------------------------------------------------------
# Base mixin
# ---------------------------------------------------------------------
class BaseModel(db.Model):
    __abstract__ = True
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ---------------------------------------------------------------------
# USERS
# ---------------------------------------------------------------------
class Users(BaseModel, UserMixin):
    __tablename__ = "users"

    fullname = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    mobile_no = db.Column(db.String(50))
    address = db.Column(db.Text)
    profile_image = db.Column(db.String(256))
    preferred_language = db.Column(db.String(50))

    is_active = db.Column(db.Boolean, default=True)
    session_token = db.Column(db.String(128))
    last_login = db.Column(db.DateTime)

    # Relationships
    consents = db.relationship("Consent", back_populates="user", cascade="all, delete-orphan")
    cookie_consents = db.relationship("CookieConsent", back_populates="user", cascade="all, delete-orphan")
    grievances = db.relationship("Grievance", back_populates="user", cascade="all, delete-orphan")
    notifications = db.relationship("Notification", back_populates="user", cascade="all, delete-orphan")
    roles = db.relationship("UserRole", back_populates="user", cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")

    # Password helpers
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    # Flask-Login
    def get_id(self):
        return self.id

    # Utility
    @property
    def primary_role(self):
        """Return first assigned role name or None."""
        return self.roles[0].role.role_name if self.roles else None

    def __repr__(self):
        return f"<User {self.email}>"

# ---------------------------------------------------------------------
# DATA FIDUCIARY
# ---------------------------------------------------------------------
class DataFiduciary(BaseModel):
    __tablename__ = "data_fiduciaries"

    name = db.Column(db.String(255), nullable=False)
    contact_email = db.Column(db.String(255), nullable=False)
    dpo_id = db.Column(db.String, db.ForeignKey("users.id"), nullable=True)

    # Relationships
    purposes = db.relationship("Purpose", back_populates="fiduciary", cascade="all, delete-orphan")
    consents = db.relationship("Consent", back_populates="fiduciary", cascade="all, delete-orphan")

# ---------------------------------------------------------------------
# PURPOSE
# ---------------------------------------------------------------------
class Purpose(BaseModel):
    __tablename__ = "purposes"

    purpose_name = db.Column(db.String(255), nullable=False, unique=True)
    description = db.Column(db.Text)
    fiduciary_id = db.Column(db.String, db.ForeignKey("data_fiduciaries.id"), nullable=False)

    # Relationships
    fiduciary = db.relationship("DataFiduciary", back_populates="purposes")
    consents = db.relationship("Consent", back_populates="purpose", cascade="all, delete-orphan")

# ---------------------------------------------------------------------
# CONSENT
# ---------------------------------------------------------------------
class Consent(BaseModel):
    __tablename__ = "consents"
    __table_args__ = (db.UniqueConstraint('user_id', name='uq_user_consent'),)

    user_id = db.Column(db.String, db.ForeignKey("users.id"), nullable=False)
    purpose_id = db.Column(db.String, db.ForeignKey("purposes.id"), nullable=False)
    fiduciary_id = db.Column(db.String, db.ForeignKey("data_fiduciaries.id"), nullable=False)

    status = db.Column(db.Enum("granted", "withdrawn", "expired", name="consent_status"), nullable=False)
    method = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime)
    language = db.Column(db.String(50))
    parent_consent_id = db.Column(db.String, db.ForeignKey("consents.id"))

    # Relationships
    user = db.relationship("Users", back_populates="consents")
    purpose = db.relationship("Purpose", back_populates="consents")
    fiduciary = db.relationship("DataFiduciary", back_populates="consents")

    parent_consent = db.relationship("Consent", remote_side="Consent.id", backref="child_consents")
    metadata_entries = db.relationship("ConsentMetadata", back_populates="consent", cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", back_populates="consent", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Consent user={self.user_id}, status={self.status}>"

# ---------------------------------------------------------------------
# CONSENT METADATA
# ---------------------------------------------------------------------
class ConsentMetadata(BaseModel):
    __tablename__ = "consent_metadata"

    consent_id = db.Column(db.String, db.ForeignKey("consents.id"), nullable=False)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(255))
    hash = db.Column(db.String(255))

    consent = db.relationship("Consent", back_populates="metadata_entries")

# ---------------------------------------------------------------------
# COOKIE CONSENT
# ---------------------------------------------------------------------
class CookieConsent(BaseModel):
    __tablename__ = "cookie_consents"

    user_id = db.Column(db.String, db.ForeignKey("users.id"), nullable=False)
    category = db.Column(db.Enum("essential", "analytics", "marketing", "performance", name="cookie_category"))
    status = db.Column(db.Enum("granted", "withdrawn", name="cookie_status"), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime)

    user = db.relationship("Users", back_populates="cookie_consents")

# ---------------------------------------------------------------------
# GRIEVANCES
# ---------------------------------------------------------------------
class Grievance(BaseModel):
    __tablename__ = "grievances"

    user_id = db.Column(db.String, db.ForeignKey("users.id"), nullable=False)
    category = db.Column(db.Enum("consent_violation", "misuse", "breach", "correction", "erasure", name="grievance_category"))
    description = db.Column(db.Text)
    status = db.Column(db.Enum("submitted", "in_progress", "resolved", "escalated", name="grievance_status"), default="submitted")
    reference_number = db.Column(db.String(100), unique=True)

    user = db.relationship("Users", back_populates="grievances")
    actions = db.relationship("GrievanceAction", back_populates="grievance", cascade="all, delete-orphan")

# ---------------------------------------------------------------------
# GRIEVANCE ACTIONS
# ---------------------------------------------------------------------
class GrievanceAction(BaseModel):
    __tablename__ = "grievance_actions"

    grievance_id = db.Column(db.String, db.ForeignKey("grievances.id"), nullable=False)
    action_taken_by = db.Column(db.String, db.ForeignKey("users.id"))
    description = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    grievance = db.relationship("Grievance", back_populates="actions")

# ---------------------------------------------------------------------
# NOTIFICATIONS
# ---------------------------------------------------------------------
class Notification(BaseModel):
    __tablename__ = "notifications"

    user_id = db.Column(db.String, db.ForeignKey("users.id"))
    fiduciary_id = db.Column(db.String, db.ForeignKey("data_fiduciaries.id"))

    type = db.Column(db.Enum("consent_update", "withdrawal", "renewal", "grievance_update", name="notification_type"))
    message = db.Column(db.Text)
    channel = db.Column(db.Enum("email", "sms", "in_app", "api", name="notification_channel"))
    status = db.Column(db.Enum("sent", "delivered", "failed", name="notification_status"), default="sent")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("Users", back_populates="notifications")

# ---------------------------------------------------------------------
# ROLES
# ---------------------------------------------------------------------
class Role(BaseModel):
    __tablename__ = "roles"

    role_name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)

    user_roles = db.relationship("UserRole", back_populates="role", cascade="all, delete-orphan")

# ---------------------------------------------------------------------
# USER ROLES
# ---------------------------------------------------------------------
class UserRole(BaseModel):
    __tablename__ = "user_roles"

    user_id = db.Column(db.String, db.ForeignKey("users.id"), nullable=False)
    role_id = db.Column(db.String, db.ForeignKey("roles.id"), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("Users", back_populates="roles")
    role = db.relationship("Role", back_populates="user_roles")

# ---------------------------------------------------------------------
# AUDIT LOGS
# ---------------------------------------------------------------------
class AuditLog(BaseModel):
    __tablename__ = "audit_logs"

    user_id = db.Column(db.String, db.ForeignKey("users.id"), nullable=False)
    consent_id = db.Column(db.String, db.ForeignKey("consents.id"), nullable=True)

    action_type = db.Column(db.Enum("grant", "withdraw", "update", "renew", "grievance", "notify", name="audit_action_type"))
    entity_type = db.Column(db.Enum("consent", "grievance", "notification", name="audit_entity_type"))
    source_ip = db.Column(db.String(50))
    hash = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("Users", back_populates="audit_logs")
    consent = db.relationship("Consent", back_populates="audit_logs")

# ---------------------------------------------------------------------
# CONTACTS / FEEDBACK
# ---------------------------------------------------------------------
class ReadStatusEnum(enum.Enum):
    Read = "Read"
    Unread = "Unread"

class Contacts(db.Model):
    __tablename__ = "contacts"
    __table_args__ = (db.CheckConstraint('rating >= 1 AND rating <= 5', name='check_rating_range'),)

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    fullname = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False, index=True)
    mobile_no = db.Column(db.String(20), nullable=False)
    address = db.Column(db.Text)
    message = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer)
    sent_on = db.Column(db.DateTime, default=datetime.utcnow)
    read_status = db.Column(db.Enum(ReadStatusEnum, name="read_status_enum"), nullable=False, default=ReadStatusEnum.Unread)

# ---------------------------------------------------------------------
# MAIL TEMPLATES
# ---------------------------------------------------------------------
class MailMessage(db.Model):
    __tablename__ = "mail_messages"

    id = db.Column(db.Integer, primary_key=True)
    template_type = db.Column(db.String(100), unique=True, nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    link_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<MailMessage {self.template_type}>"
    
# ---------------------------------------------------------------------
# Consent Forms
# ---------------------------------------------------------------------
class ConsentForm(db.Model):
    __tablename__ = "consent_forms"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    form_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)

    # Each form can have multiple fields (input, checkbox, select)
    fields = db.relationship("FormField", back_populates="form", cascade="all, delete-orphan")

class FormField(db.Model):
    __tablename__ = "form_fields"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    form_id = db.Column(db.Integer, db.ForeignKey("consent_forms.id"), nullable=False)

    label = db.Column(db.String(255), nullable=False)
    field_type = db.Column(db.String(50), nullable=False)  # e.g., text, email, checkbox, select
    options = db.Column(db.Text, nullable=True)  # comma-separated values for select
    required = db.Column(db.Boolean, default=False)

    form = db.relationship("ConsentForm", back_populates="fields")
