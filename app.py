from flask import Flask, render_template, request, g, redirect, url_for, flash, session
import sqlite3
from datetime import date

import os
import hashlib
import binascii
import random
import string



app_info = {
    'db_file': 'C:\\Users\\miesz\\Documents\\GitHub\\Ostateczna\\data\\cantor.db'
}

app = Flask(__name__)

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

def get_db():
    if not hasattr(g, 'sqlite_db'):
        conn = sqlite3.connect(app_info['db_file'])
        conn.row_factory = sqlite3.Row
        g.sqlite_db = conn
    return g.sqlite_db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


@app.route('/login', methods=['GET','POST'])
def login():

    if request.method == 'GET':
        return render_template('login.html', active_menu='login')
    else:
        user_name = '' if 'user_name' not in request.form else request.form['user_name']
        user_pass = '' if 'user_pass' not in request.form else request.form['user_pass']

    login = UserPass(user_name, user_pass)
    login_record = login.login_user()

    if login_record != None:
        session['user'] = user_name
        flash('Logon succesfull, welcome {}'.format(user_name))
        return redirect(url_for('index'))
    else:
        flash('Logon failed, try again')
        return render_template('login.html')

@app.route('/logout')
def logout():

    if 'user' in session:
        session.pop('user', None)
        flash('You are logged out')
    return redirect(url_for('login'))

class UserPass:
    def __init__(self, user='', password=''):
        self.user = user
        self.password = password

    def hash_password(self):
        # Hash a password for storing.
        os_urandom_static = b"ID_\x12p:\x8d\xe7&\xcb\xf0=H1\xc1\x16\xac\xe5BX\xd7\xd6j\xe3i\x11\xbe\xaa\x05\xccc\xc2\xe8K\xcf\xf1\xac\x9bFy(\xfbn.`\xe9\xcd\xdd'\xdf`~vm\xae\xf2\x93WD\x04"
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha512', self.password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')

    def verify_password(self, stored_password, provided_password):
        # Verify a stored password against one provided by the user.
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'), salt.encode('ascii'), 100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password

    def get_random_user_password(self):
        random_user = ''.join(random.choice(string.ascii_lowercase) for _ in range(3))
        self.user = random_user

        password_characters = string.ascii_letters  # + string.digits + string.punctuation
        random_password = ''.join(random.choice(password_characters) for _ in range(3))
        self.password = random_password
    
    def login_user(self):
        db = get_db()
        sql_statement = 'select id, name, email, password, is_active, is_admin from users where name=?'
        cur = db.execute(sql_statement, [self.user])
        user_record = cur.fetchone()
        if user_record != None and self.verify_password(user_record['password'], self.password):
            return user_record
        else:
            self.user = None
            self.password = None
            return None 
        
@app.route('/init_app')
def init_app():

    # check if there are users defined (at least one active admin required)
    db = get_db()
    sql_statement = 'select count(*) as cnt from users where is_active and is_admin;'
    cur = db.execute(sql_statement)
    active_admins = cur.fetchone()

    if active_admins!=None and active_admins['cnt']>0:
        flash('Application is already set-up. Nothing to do')
        return redirect(url_for('index'))

 # if not - create/update admin account with a new password and admin privileges, display

    user_pass = UserPass()
    user_pass.get_random_user_password()
    sql_statement = '''insert into users(name, email, password, is_active, is_admin)
    values(?,?,?,True, True);'''
    db.execute(sql_statement, [user_pass.user, 'noone@nowhere.no', user_pass.hash_password()])
    db.commit()
    flash('User {} with password {} has been created'.format(user_pass.user, user_pass.password))
    return redirect(url_for('index')) 

@app.route('/users')
def users():
    db = get_db()
    sql_command = 'select id, name, email, is_admin, is_active from users;'
    cur = db.execute(sql_command)
    users=cur.fetchall()
    return render_template('users.html', active_menu='users', users=users)

@app.route('/user_status_change/<action>/<user_name>')
def user_status_change(action, user_name):
	return 'not implemented'

@app.route('/edit_user/<user_name>', methods=['GET', 'POST'])
def edit_user(user_name):

    db = get_db()
    cur = db.execute('select name, email from users where name = ?', [user_name])
    user = cur.fetchone()
    message = None

    if user == None:
        flash('No such user')
        return redirect(url_for('users'))

    if request.method == 'GET':
        return render_template('edit_user.html', active_menu='users', user=user)
    else:
        new_email = '' if 'email' not in request.form else request.form["email"]
        new_password = '' if 'user_pass' not in request.form else request.form['user_pass']

        if new_email != user['email']:
            sql_statement = "update users set email = ? where name = ?"
            db.execute(sql_statement, [new_email, user_name])
            db.commit()
            flash('Email was changed')

        if new_password != '':
            user_pass = UserPass(user_name, new_password)
            sql_statement = "update users set password = ? where name = ?"
            db.execute(sql_statement, [user_pass.hash_password(), user_name])
            db.commit()
            flash('Password was changed')

        return redirect(url_for('users'))

@app.route('/user_delete/<user_name>')
def delete_user(user_name):
	
    if not 'user' in session:
        return redirect(url_for('login'))
    login = session['user']

    db=get_db()
    sql_statement = "delete from users where name = ? and name <> ?"
    db.execute(sql_statement, [user_name, login])
    db.commit()
    return redirect(url_for('users'))

@app.route('/new_user', methods=['GET', 'POST'])
def new_user():
    if not 'user' in session:
        return redirect(url_for('login'))

    login = session['user']
    db = get_db()
    message = None
    user = {}

    if request.method == 'GET':
        return render_template('new_user.html', active_menu='users', user=user)
    else:
        user['user_name'] = '' if not 'user_name' in request.form else request.form['user_name']
        user['email'] = '' if not 'email' in request.form else request.form['email']
        user['user_pass'] = '' if not 'user_pass' in request.form else request.form['user_pass']
        cursor = db.execute('select count(*) as cnt from users where name = ?',[user['user_name']])
        record = cursor.fetchone()
        is_user_name_unique = (record['cnt'] == 0)

        cursor = db.execute('select count(*) as cnt from users where email = ?', [user['email']])
        record = cursor.fetchone()
        is_user_email_unique = (record['cnt'] == 0)
    
        if user['user_name'] == '':
            message = 'Name cannot be empty'
        elif user['email'] == '':
            message = 'email cannot be empty'
        elif user['user_pass'] == '':
            message = 'Password cannot be empty'
        elif not is_user_name_unique:
            message = 'User with the name {} already exists'.format(user['user_name'])
        elif not is_user_email_unique:
            message = 'User with the email {} alresdy exists'.format(user['email']) 
    
        if not message:
            user_pass = UserPass(user['user_name'], user['user_pass'])
            password_hash = user_pass.hash_password()
            sql_statement = '''insert into users(name, email, password, is_active, is_admin) values(?,?,?, True, False);'''
            db.execute(sql_statement, [user['user_name'], user['email'], password_hash])
            db.commit()
            flash('User {} created'.format(user['user_name']))
            return redirect(url_for('users'))
        else:
            flash('Correct error: {}'.format(message))
            return render_template('new_user.html', active_menu='users', user=user)

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/exchange', methods=['GET', 'POST'])
def exchange():
    if request.method == 'GET':
        return render_template('exchange.html')
    else:
        amount = 100
        if 'amount' in request.form:
            amount = request.form['amount']

        currency = "EUR"
        if 'currency' in request.form:
            currency = request.form['currency']
        
        db = get_db()
        sql_command = 'insert into transactions (currency, amount, user) values (?, ?, ?);'
        db.execute(sql_command, [currency, amount, 'admin'])
        db.commit()
        return render_template('exchange_results.html', currency=currency, amount=amount)

@app.route('/history')    
def history():
    db=get_db()
    sql_command='select id, currency, amount, trans_date from transactions;'
    cur = db.execute(sql_command)
    transactions = cur.fetchall()

    return render_template('history.html', transactions=transactions)

@app.route('/delete_transaction/<int:transaction_id>')
def delete_transaction(transaction_id):
    db = get_db()
    sql_statement='delete from transactions where id=?;'
    db.execute(sql_statement, [transaction_id])
    db.commit()
    flash('usunieto!')
    return redirect(url_for('history'))

@app.route('/edit_transaction/<int:transaction_id>', methods=['GET', 'POST'])
def edit_transaction(transaction_id):
    db = get_db()

    if request.method == 'GET':
        sql_statement = 'select id, currency, amount from transactions where id=?;'
        cur = db.execute(sql_statement, [transaction_id])
        transaction = cur.fetchone()

        if transaction is None:
            flash('No such transaction!')
            return redirect(url_for('history'))
        else:
            return render_template('edit_transaction.html', transaction=transaction)
    elif request.method == 'POST':
        amount = 100
        if 'amount' in request.form:
            amount = request.form['amount']

        currency = "EUR"
        if 'currency' in request.form:
            currency = request.form['currency']
        
        sql_command = 'update transactions set currency=?, amount=?, user=?, trans_date=? where id=?;'
        db.execute(sql_command, [currency, amount, 'admin', date.today(), transaction_id])
        db.commit()
        return redirect(url_for('history'))  # Redirect to 'history' after successful update
