from mimetypes import inited
from app import app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(120), nullable=True)
    address = db.Column(db.String(120), nullable=True)
    pincode = db.Column(db.String(120), nullable=True)
    aadhaar = db.Column(db.String(120), nullable=True)
    pan = db.Column(db.String(120), nullable=True)
    service_name = db.Column(db.String(120), nullable=True)
    experience = db.Column(db.String(120), nullable=True)
    allow_status = db.Column(db.Enum('allowed','rejected','pending'), nullable=False, default='pending')
    block = db.Column(db.Enum('unblocked','blocked'), nullable=False, default='unblocked')
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_customer = db.Column(db.Boolean, nullable=False, default=False)
    is_professional = db.Column(db.Boolean, nullable=False, default=False)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Customer(db.Model):
    __tablename__ = 'customer'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    customers = db.relationship('User', backref='customer')

class Professional(db.Model):
    __tablename__ = 'professional'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    professionals = db.relationship('User', backref='professional')

class Service(db.Model):
    __tablename__ = 'service'
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(120), nullable=True)
    service_description = db.Column(db.String(120), nullable=True)
    service_time = db.Column(db.String(120), nullable=True)
    service_cost = db.Column(db.String(120), nullable=True)

    services = db.relationship('ServiceRequest', backref='service')

class ServiceRequest(db.Model):
    __tablename__ = 'servicerequest'
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('professional.id'), nullable=True)
    description = db.Column(db.Text, nullable=True)
    date_of_request = db.Column(db.DateTime, nullable=False)
    service_status = db.Column(db.Enum('requested', 'accepted', 'declined', 'closed'), nullable=False, default='requested')
    service_rating = db.Column(db.Integer, nullable=True)
    remarks = db.Column(db.Text, nullable=True)
    
with app.app_context():
    db.create_all()

    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username = 'admin',email = 'admin@gmail.com', password = 'admin', is_admin = True)
        db.session.add(admin)
        db.session.commit()