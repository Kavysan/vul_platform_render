from flask import Blueprint, request, render_template, request,redirect, url_for, flash, session
from werkzeug.security import check_password_hash
from models import User
from app import db  
auth = Blueprint('auth', __name__, template_folder='auth')


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