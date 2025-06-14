from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import date

from app import app

from models import db, User, Customer, Professional, Service, ServiceRequest

def auth_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to login first.')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return inner

def get_current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

@app.route('/login')
def login():
    return render_template('login.html', user=None)

@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    if email == '' or password == '':
        flash('Email or Password cannot be empty.')
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User does not exist.')
        return redirect(url_for('login'))
    if not user.check_password(password):
        flash('Incorrect password.')
        return redirect(url_for('login'))
    
    session['user_id'] = user.id

    if user.is_admin:
        return redirect(url_for('admin'))
    elif user.is_customer and user.block == 'unblocked':
        return redirect(url_for('customer'))
    elif user.is_customer and user.block == 'blocked':
        flash('You are blocked by Admin.')
        session.pop('user_id')
        return redirect(url_for('login'))
    elif user.is_professional and user.allow_status == 'allowed' and user.block == 'unblocked':
        return redirect(url_for('professional'))
    elif user.is_professional and user.allow_status == 'allowed' and user.block == 'blocked':
        flash('You are blocked by Admin.')
        session.pop('user_id')
        return redirect(url_for('login'))
    elif user.is_professional and user.allow_status == 'rejected':
        flash('Your request is rejected. Please contact admin for more information.')
        session.pop('user_id')
        return redirect(url_for('login'))
    elif user.is_professional and user.allow_status == 'pending':
        flash('Your request is pending. Please wait for admin approval.')
        session.pop('user_id')
        return redirect(url_for('login'))
    else:
        return redirect(url_for('index'))
    
@app.route('/Customer_Registration')
def Customer_Registration():
    return render_template('Customer_Registration.html')

@app.route('/Customer_Registration', methods=['POST'])
def Customer_Registration_post():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    cpassword = request.form.get('cpassword')
    address = request.form.get('address')
    pincode = request.form.get('pincode')
    phone = request.form.get('phone')
    if username == '' or email == '' or password == '' or cpassword == '':
        flash('Name, Email or Password cannot be empty.')
        return redirect(url_for('Customer_Registration'))
    if password != cpassword:
        flash('Passwords do not match.')
        return redirect(url_for('Customer_Registration'))
    if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
        flash('User already exists.')
        return redirect(url_for('Customer_Registration'))
    user = User(username=username, email=email, password=password, phone=phone, address=address, pincode=pincode, is_customer=True)
    db.session.add(user)
    db.session.flush()
    customer = Customer(user_id=user.id)
    db.session.add(customer)
    db.session.commit()
    flash('User registered successfully.')
    return redirect(url_for('login'))

@app.route('/Professional_Registration')
def Professional_Registration():
    customers = User.query.filter_by(is_customer=True).all()
    return render_template('Professional_Registration.html', services=Service.query.all(), customers=customers)

@app.route('/Professional_Registration', methods=['POST'])
def Professional_Registration_post():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    cpassword = request.form.get('cpassword')
    address = request.form.get('address')
    pincode = request.form.get('pincode')
    service_name = request.form.get('service_name')
    experience = request.form.get('experience')
    phone = request.form.get('phone')
    aadhaar = request.form.get('aadhaar')
    pan = request.form.get('pan')
    allow_status = 'pending'

    if username == '' or email == '' or password == '' or cpassword == '':
        flash('Name, Email or Password cannot be empty.')
        return redirect(url_for('Professional_Registration'))
    if password != cpassword:
        flash('Passwords do not match.')
        return redirect(url_for('Professional_Registration'))
    if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
        flash('User already exists.')
        return redirect(url_for('Professional_Registration'))
    if aadhaar == '' or pan == '':
        flash('Aadhaar or Pan cannot be empty.')
        return redirect(url_for('Professional_Registration'))
    user = User(username=username, email=email, password=password, phone=phone,address=address, pincode=pincode, service_name=service_name, experience=experience, aadhaar=aadhaar, pan=pan, is_professional=True, allow_status=allow_status)
    db.session.add(user)
    db.session.flush()
    professional = Professional(user_id=user.id)
    db.session.add(professional)
    db.session.commit()
    flash('User registered successfully.')
    return redirect(url_for('login'))

@app.route('/admin')
@auth_required
def admin():
    user = User.query.get(session['user_id'])
    customers = User.query.filter_by(is_customer=True).all()
    professionals = User.query.filter_by(is_professional=True).all()
    if not user.is_admin:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    return render_template('admin.html', user=user, customers=customers, professionals=professionals, services=Service.query.all(), servicerequests=ServiceRequest.query.all())

@app.route('/customer')
@auth_required
def customer():
    user = User.query.get(session['user_id'])
    professionals = User.query.filter_by(is_professional=True).all()
    if not user.is_customer:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    return render_template('customer.html', user=user, servicerequests=ServiceRequest.query.filter_by(customer_id=user.id), professionals=professionals)

@app.route('/professional')
@auth_required
def professional():
    user = User.query.get(session['user_id'])
    services = Service.query.all()
    if not user.is_professional:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    return render_template('professional.html', user=user, services=services, servicerequests=ServiceRequest.query.filter_by(professional_id=user.username), customers=User.query.filter_by(is_customer=True))

@app.route('/')
@auth_required
def index():
    user = get_current_user()
    customers = User.query.filter_by(is_customer=True).all()
    professionals = User.query.filter_by(is_professional=True).all()
    if user is None:
        flash('User not found.')
        return redirect(url_for('login'))
    if user.is_admin:
        return redirect(url_for('admin'))
    elif user.is_customer:
        return redirect(url_for('customer'))
    elif user.is_professional:
        return redirect(url_for('professional'))
    else:
        return render_template('index.html', user=user, customers=customers, professionals=professionals)

@app.route('/search')
@auth_required
def search():
    user = User.query.get(session['user_id'])
    services = Service.query.all()
    professionals = User.query.filter_by(is_professional=True).all()
    return render_template('search.html', user=user, services=services, professionals=professionals)

@app.route('/search', methods=['POST'])
@auth_required
def search_post():
    user = User.query.get(session['user_id'])
    if user.is_professional:
        return redirect(url_for('index'))
    
    services = Service.query.all()
    professionals = User.query.filter_by(is_professional=True).all()

    search_parameter = request.form.get('search_parameter')
    search_query = request.form.get('search_query')

    print(search_parameter, search_query)

    if not search_parameter or not search_query:
        return render_template('search.html', user=user, services=services, professionals=professionals)
    
    if search_parameter == 'username':
        professionals = User.query.filter(User.username.like(f'%{search_query}%')).filter_by(is_professional=True).all()

    if search_parameter == 'service_name':
        professionals = User.query.filter(User.service_name.like(f'%{search_query}%')).filter_by(is_professional=True).all()

    if search_parameter == 'address':
        professionals = User.query.filter(User.address.like(f'%{search_query}%')).filter_by(is_professional=True).all()
    
    if search_parameter == 'pincode':
        professionals = User.query.filter(User.pincode.like(f'%{search_query}%')).filter_by(is_professional=True).all()

    return render_template('search.html', user=user, services=services, professionals=professionals, search_parameter=search_parameter, search_query=search_query)

@app.route('/profile')
@auth_required
def profile():
    return render_template('profile.html', user=User.query.get(session['user_id']), customer=Customer.query.filter_by(user_id=session['user_id']).first(), professional=Professional.query.filter_by(user_id=session['user_id']).first())

@app.route('/profile', methods=['POST'])
@auth_required
def profile_post():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    cpassword = request.form.get('cpassword')
    address = request.form.get('address')
    pincode = request.form.get('pincode')
    phone = request.form.get('phone')

    if username == '':
        flash('Name cannot be empty.')
        return redirect(url_for('profile'))
    
    if email == '':
        flash('Email cannot be empty.')
        return redirect(url_for('profile'))
    
    if password == '' or cpassword == '':
        flash('Password cannot be empty.')
        return redirect(url_for('profile'))
    
    if address == '':
        flash('Address cannot be empty.')
        return redirect(url_for('profile'))
    
    if pincode == '':
        flash('Pincode cannot be empty.')
        return redirect(url_for('profile'))
    
    if phone == '':
        flash('Phone cannot be empty.')
        return redirect(url_for('profile'))
    
    user = User.query.get(session['user_id'])

    if not check_password_hash(user.password_hash, cpassword):
        flash('Incorrect password.')
        return redirect(url_for('profile'))
    
    if username != user.username:
        new_username = User.query.filter_by(username=username).first()
        if new_username:
            flash('Username already exists.')
            return redirect(url_for('profile'))
        
    new_password_hash = generate_password_hash(password)
    user.username = username
    user.email = email
    user.password_hash = new_password_hash
    user.address = address
    user.pincode = pincode
    user.phone = phone
    db.session.commit()
    flash('Profile updated successfully.')
    return redirect(url_for('profile'))
    
@app.route('/logout')
@auth_required
def logout():
    session.pop('user_id')
    return redirect(url_for('login'))

@app.route('/service/add')
@auth_required
def add_service():
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    return render_template('service/add.html', user=user)

@app.route('/service/add', methods=['POST'])
@auth_required
def add_service_post():
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    
    service_name = request.form.get('service_name')
    service_description = request.form.get('service_description')
    service_time = request.form.get('service_time')
    service_cost = request.form.get('service_cost')

    if service_name == '':
        flash('Service Name cannot be empty.')
        return redirect(url_for('add_service'))
    
    if service_description == '':
        flash('Service Description cannot be empty.')
        return redirect(url_for('add_service'))
    
    if service_time == '':
        flash('Service Time cannot be empty.')
        return redirect(url_for('add_service'))

    if service_cost == '':
        flash('Service Cost cannot be empty.')
        return redirect(url_for('add_service'))
    
    service = Service(service_name=service_name, service_description=service_description, service_time=service_time, service_cost=service_cost)
    db.session.add(service)
    db.session.commit()
    flash('Service added successfully.')
    return redirect(url_for('admin'))

@app.route('/service/<int:id>/edit')
@auth_required
def edit_service(id):
    return render_template('service/edit.html', user=User.query.get(session['user_id']), service=Service.query.get(id))

@app.route('/service/<int:id>/edit', methods=['POST'])
@auth_required
def edit_service_post(id):
    service = Service.query.get(id)

    service_name = request.form.get('service_name')
    service_description = request.form.get('service_description')
    service_time = request.form.get('service_time')
    service_cost = request.form.get('service_cost')

    if service_name == '':
        flash('Service Name cannot be empty.')
        return redirect(url_for('edit_service', id=id))
    
    if service_description == '':
        flash('Service Description cannot be empty.')
        return redirect(url_for('edit_service', id=id))
    
    if service_time == '':
        flash('Service Time cannot be empty.')
        return redirect(url_for('edit_service', id=id))

    if service_cost == '':
        flash('Service Cost cannot be empty.')
        return redirect(url_for('edit_service', id=id))
    
    service.service_name = service_name
    service.service_description = service_description
    service.service_time = service_time
    service.service_cost = service_cost
    db.session.commit()
    flash('Service updated successfully.')
    return redirect(url_for('admin'))

@app.route('/service/<int:id>/delete')
@auth_required
def delete_service(id):
    return render_template('service/delete.html', user=User.query.get(session['user_id']), service=Service.query.get(id))

@app.route('/service/<int:id>/delete', methods=['POST'])
@auth_required
def delete_service_post(id):
    service = Service.query.get(id)
    if not service:
        flash('Service not found.')
        return redirect(url_for('admin'))
    db.session.delete(service)
    db.session.commit()
    flash('Service deleted successfully.')
    return redirect(url_for('admin'))

@app.route('/service_request/create')
@auth_required
def create_service_request():
    user = User.query.get(session['user_id'])
    if not user.is_customer:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    return render_template('service_request/create.html', user=user, services=Service.query.all(), professionals=User.query.filter_by(is_professional=True))

@app.route('/service_request/create', methods=['POST'])
@auth_required
def create_service_request_post():
    user = User.query.get(session['user_id'])
    if not user.is_customer:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    service_id = request.form.get('service_id')
    customer_id = user.id
    professional_id = request.form.get('professional_id')
    description = request.form.get('description')
    date_of_request = date.today()
    service_status = 'requested'
    service_rating = ''
    remarks = ''

    if service_id == '':
        flash('Service Name cannot be empty.')
        return redirect(url_for('add_service'))
    
    if professional_id == '':
        flash('Professional Name cannot be empty.')
        return redirect(url_for('add_professional'))

    if description == '':
        flash('Service Description cannot be empty.')
        return redirect(url_for('add_service'))
    
    servicerequest = ServiceRequest(service_id=service_id, customer_id=customer_id, professional_id=professional_id, description=description, date_of_request=date_of_request, service_status=service_status, service_rating=service_rating, remarks=remarks)
    db.session.add(servicerequest)
    db.session.commit()
    flash('Service added successfully.')
    return redirect(url_for('customer'))

@app.route('/service_request/<int:id>/edit_req')
@auth_required
def edit_req_service_request(id):
    return render_template('service_request/edit_req.html', user=User.query.get(session['user_id']), servicerequest=ServiceRequest.query.get(id), services=Service.query.all(), professionals=User.query.filter_by(is_professional=True))

@app.route('/service_request/<int:id>/edit_req', methods=['POST'])
@auth_required
def edit_req_service_request_post(id):
    servicerequest = ServiceRequest.query.get(id)

    description = request.form.get('description')
    date_of_request = date.today()
    
    if description == '':
        flash('Service Description cannot be empty.')
        return redirect(url_for('edit_req_service_request', id=id))
    
    servicerequest.description = description
    servicerequest.date_of_request = date_of_request
    db.session.commit()
    flash('Service updated successfully.')
    return redirect(url_for('customer'))

@app.route('/service_request/<int:id>/close')
@auth_required
def close_service_request(id):
    return render_template('service_request/close.html', user=User.query.get(session['user_id']), servicerequest=ServiceRequest.query.get(id), professionals=User.query.filter_by(is_professional=True))

@app.route('/service_request/<int:id>/close', methods=['POST'])
@auth_required
def close_service_request_post(id):
    user = User.query.get(session['user_id'])
    if not user.is_customer:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    
    servicerequest = ServiceRequest.query.get(id)
    if not servicerequest:
        flash('Service request not found.')
        return redirect(url_for('index'))
    
    if servicerequest.customer_id != user.id:
        flash('You are not authorized to close this service request.')
        return redirect(url_for('index'))
    
    rating = request.form.get('rating')
    remarks = request.form.get('remarks')
    
    if not rating or not rating.isdigit() or int(rating) < 1 or int(rating) > 5:
        flash('Please provide a valid rating (1-5).')
        return redirect(url_for('close_servicerequest', id=id))
    
    servicerequest.service_status = 'closed'
    servicerequest.service_rating = int(rating)
    servicerequest.remarks = remarks
    db.session.commit()
    flash('Service request closed.')
    return redirect(url_for('customer'))

@app.route('/service_request/<int:id>/accept')
@auth_required
def accept_service_request(id):
    return render_template('service_request/accept.html', user=User.query.get(session['user_id']), servicerequest=ServiceRequest.query.get(id))

@app.route('/service_request/<int:id>/accept', methods=['POST'])
@auth_required
def accept_service_request_post(id):
    user = User.query.get(session['user_id'])
    if not user.is_professional:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    
    servicerequest = ServiceRequest.query.get(id)
    if not servicerequest:
        flash('Service request not found.')
        return redirect(url_for('index'))
    
    if servicerequest.professional_id != user.username:
        flash('You are not authorized to accept this service request.')
        return redirect(url_for('index'))
    
    servicerequest.service_status = 'accepted'
    db.session.commit()
    flash('Service request accepted.')
    return redirect(url_for('professional'))

@app.route('/service_request/<int:id>/decline')
@auth_required
def decline_service_request(id):
    return render_template('service_request/decline.html', user=User.query.get(session['user_id']), servicerequest=ServiceRequest.query.get(id))

@app.route('/service_request/<int:id>/decline', methods=['POST'])
@auth_required
def decline_service_request_post(id):
    user = User.query.get(session['user_id'])
    if not user.is_professional:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    
    servicerequest = ServiceRequest.query.get(id)
    if not servicerequest:
        flash('Service request not found.')
        return redirect(url_for('index'))
    
    if servicerequest.professional_id != user.username:
        flash('You are not authorized to decline this service request.')
        return redirect(url_for('index'))
    
    servicerequest.service_status = 'declined'
    db.session.commit()
    flash('Service request declined.')
    return redirect(url_for('professional'))

@app.route('/service_request/<int:id>/delete_req')
@auth_required
def delete_req_service_request(id):
    return render_template('service_request/delete_req.html', user=User.query.get(session['user_id']), servicerequest=ServiceRequest.query.get(id))

@app.route('/service_request/<int:id>/delete_req', methods=['POST'])
@auth_required
def delete_req_service_request_post(id):
    servicerequest = ServiceRequest.query.get(id)
    if not servicerequest:
        flash('Service request not found.')
        return redirect(url_for('customer'))
    db.session.delete(servicerequest)
    db.session.commit()
    flash('Service request deleted successfully.')
    return redirect(url_for('customer'))

@app.route('/professional/<int:id>/allowed')
@auth_required
def allowed_professional(id):
    return render_template('professional/allowed.html', user=User.query.get(session['user_id']), professional = User.query.filter_by(id=id, is_professional=True).first())

@app.route('/professional/<int:id>/allowed', methods=['POST'])
@auth_required
def allowed_professional_post(id):
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    
    professional = User.query.filter_by(id=id, is_professional=True).first()
    if not professional:
        flash('Request not found.')
        return redirect(url_for('index'))
    
    professional.allow_status = 'allowed'
    db.session.commit()
    flash('Professional is Allowed to do Services.')
    return redirect(url_for('admin'))

@app.route('/professional/<int:id>/rejected')
@auth_required
def rejected_professional(id):
    return render_template('professional/rejected.html', user=User.query.get(session['user_id']), professional = User.query.filter_by(id=id, is_professional=True).first())

@app.route('/professional/<int:id>/rejected', methods=['POST'])
@auth_required
def rejected_professional_post(id):
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    
    professional = User.query.filter_by(id=id, is_professional=True).first()
    if not professional:
        flash('Request not found.')
        return redirect(url_for('index'))
    
    professional.allow_status = 'rejected'
    db.session.commit()
    flash("Professional's request is Rejected.")
    return redirect(url_for('admin'))

@app.route('/live_users')
@auth_required
def live_users():
    return render_template('live_users.html', user=User.query.get(session['user_id']), customers=User.query.filter_by(is_customer=True), professionals=User.query.filter_by(is_professional=True))

@app.route('/live_users', methods=['POST'])
@auth_required
def live_users_post():
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    return render_template('live_users.html', user=user, customers=User.query.filter_by(is_customer=True), professionals=User.query.filter_by(is_professional=True))
    
@app.route('/user/<int:id>/block_customer')
@auth_required
def block_customer(id):
    return render_template('user/block_customer.html', user=User.query.get(session['user_id']), customer = User.query.filter_by(id=id, is_customer=True).first())

@app.route('/user/<int:id>/block_customer', methods=['POST'])
@auth_required
def block_customer_post(id):
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    
    customer = User.query.filter_by(id=id, is_customer=True).first()
    if not customer:
        flash('Request not found.')
        return redirect(url_for('index'))
    
    customer.block = 'blocked'
    db.session.commit()
    flash('Customer is Blocked.')
    return redirect(url_for('live_users'))

@app.route('/user/<int:id>/unblock_customer')
@auth_required
def unblock_customer(id):
    return render_template('user/unblock_customer.html', user=User.query.get(session['user_id']), customer = User.query.filter_by(id=id, is_customer=True).first())

@app.route('/user/<int:id>/unblock_customer', methods=['POST'])
@auth_required
def unblock_customer_post(id):
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    
    customer = User.query.filter_by(id=id, is_customer=True).first()
    if not customer:
        flash('Request not found.')
        return redirect(url_for('index'))
    
    customer.block = 'unblocked'
    db.session.commit()
    flash('Customer is Unblocked.')
    return redirect(url_for('live_users'))

@app.route('/user/<int:id>/block_professional')
@auth_required
def block_professional(id):
    return render_template('user/block_professional.html', user=User.query.get(session['user_id']), professional = User.query.filter_by(id=id, is_professional=True).first())

@app.route('/user/<int:id>/block_professional', methods=['POST'])
@auth_required
def block_professional_post(id):
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    
    professional = User.query.filter_by(id=id, is_professional=True).first()
    if not professional:
        flash('Request not found.')
        return redirect(url_for('index'))
    
    professional.block = 'blocked'
    db.session.commit()
    flash('Professional is Blocked.')
    return redirect(url_for('live_users'))

@app.route('/user/<int:id>/unblock_professional')
@auth_required
def unblock_professional(id):
    return render_template('user/unblock_professional.html', user=User.query.get(session['user_id']), professional = User.query.filter_by(id=id, is_professional=True).first())

@app.route('/user/<int:id>/unblock_professional', methods=['POST'])
@auth_required
def unblock_professional_post(id):
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    
    professional = User.query.filter_by(id=id, is_professional=True).first()
    if not professional:
        flash('Request not found.')
        return redirect(url_for('index'))
    
    professional.block = 'unblocked'
    db.session.commit()
    flash('Professional is Unblocked.')
    return redirect(url_for('live_users'))