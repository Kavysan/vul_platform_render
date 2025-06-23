from flask import Blueprint, request, render_template, request,redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash
from models import User
from app import db  
from functools import wraps

auth = Blueprint('auth', __name__, template_folder='auth')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in') or session.get('user_role') != 'admin':
            flash('Admin access required.')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(email=username).first()

        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['user_email'] = user.email
            session['user_role'] = user.role
            flash('Login successful!', 'success')
            return redirect(url_for('api.files'))
        else:
            flash('Invalid username or password. Try Again!')
            return render_template('login.html')
    return render_template('login.html')

@auth.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('auth.login'))

@auth.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@auth.route('/admin/add_user', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        if User.query.filter_by(email=email).first():
            flash('User already exists.')
            return redirect(url_for('auth.add_user'))

        hashed_pw = generate_password_hash(password)
        new_user = User(email=email, password=hashed_pw, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('User added successfully.')
        return redirect(url_for('auth.admin_dashboard'))

    return render_template('add_user.html')

@auth.route('/admin/delete_user/<user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    # Prevent deleting admin users
    if user.role == 'admin':
        flash("You cannot delete an admin user.", "warning")
        return redirect(url_for('auth.admin_dashboard'))

    # Optional: Prevent admin deleting their own account
    if user.email == session.get('user_email'):
        flash("You cannot delete your own admin account.", "warning")
        return redirect(url_for('auth.admin_dashboard'))

    db.session.delete(user)
    db.session.commit()
    flash(f"User '{user.email}' deleted successfully.", "success")
    return redirect(url_for('auth.admin_dashboard'))