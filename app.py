from flask import Flask, render_template, request, g, redirect, url_for, flash, session
import psycopg2
from datetime import date
from psycopg2.extras import DictCursor
import os
import hashlib
import binascii
import random
import string
import psycopg2.extras

app = Flask(__name__)

if __name__ == '__main__':
    app.run(debug=True)

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

def get_db():
    if not hasattr(g, 'db'):
        dbname = 'OpenWorkFlow'
        user = 'postgres'
        password = 'a'
        host = 'localhost'
        port = '5432'
        conn = psycopg2.connect(dbname=dbname, user=user, password=password, host=host, port=port)
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()

@app.route('/init_app')
def init_app():
    db = get_db()
    cur = db.cursor()

    # check if there are users defined (at least one active admin required)
    cur.execute("SELECT COUNT(*) FROM users WHERE is_active = TRUE AND is_admin = TRUE")
    active_admins = cur.fetchone()[0]

    if active_admins > 0:
        flash('Application is already set-up. Nothing to do')
        return redirect(url_for('index'))

    # if not - create/update admin account with a new password and admin privileges, display
    user_pass = UserPass()
    user_pass.get_random_user_password()
    name = user_pass.user[:100]  # truncate the name to 100 characters
    email = 'noone@nowhere.no'
    password = user_pass.hash_password()
    sql_statement = "INSERT INTO users (name, email, password, is_active, is_admin) VALUES (%s, %s, %s, %s, %s)"
    cur.execute(sql_statement, [name, email, password, True, True])
    db.commit()
    flash('User {} with password {} has been created'.format(user_pass.user, user_pass.password))
    return redirect(url_for('index'))

@app.route('/login', methods=['GET','POST'])
def login():

    login = UserPass(session.get('user'))
    login.get_user_info()

    if request.method == 'GET':
        return render_template('login.html', active_menu='login', login=login)
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
        self.email = ''
        self.is_valid = False
        self.is_active = False

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
        sql_statement = 'select id, name, email, password, is_active, is_admin from users where name=%s'
        cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute(sql_statement, [self.user])
        user_record = cur.fetchone()
        if user_record != None and self.verify_password(user_record['password'], self.password):
            return user_record
        else:
            self.user = None
            self.password = None
            return None
        
    def get_user_info(self):
        db = get_db()
        sql_statement = 'select name, email, is_active, is_admin from users where name=%s'
        cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute(sql_statement, [self.user])
        db_user = cur.fetchone()

        if db_user == None:
            self.is_valid = False
            self.is_admin = False
            self.email = ''
        elif db_user['is_active']!=1:
            self.is_valid = False
            self.is_admin = False
            self.email = db_user['email']
        else:
            self.is_valid = True
            self.is_admin = db_user['is_admin']
            self.email = db_user['email']       
        
@app.route('/users')
def users():
    # Check if user is logged in and is an admin
    #login = UserPass(session.get('user'))
    #login.get_user_info()
    #if not login.is_valid or not login.is_admin:
    #    flash(f'Użytkownik {login.user} nie jest adminem')
    #    return redirect(url_for('login'))
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        flash(f'Użytkownik {login.user} nie aktywny')
        return redirect(url_for('login'))


    db = get_db()
    sql_command = 'select id, name, email, is_admin, is_active from users;'
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(sql_command)
    users=cur.fetchall()

    return render_template('users.html', active_menu='users', users=users, login=login)

@app.route('/user_status_change/<action>/<user_name>')
def user_status_change(action, user_name):

    # app.py – code to add to functions – admin access

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash(f'Użytkownik {login.user} nie jest adminem')
        return redirect(url_for('login'))

    #if not 'user' in session:
    #    return redirect(url_for('login'))
    #login = session['user']
    #flash(f'user name {user_name} login {login}')
    db = get_db()

    if action == 'active':
        cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        #tatus_sql='select is_active from users where name='aaa';'
        cur.execute("update users set is_active = ((is_active::int + 1) %% 2)::boolean where name = %s and name <> %s ", (user_name, login.user))       
        db.commit()
    elif action == 'admin':
        cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("update users set is_admin = ((is_admin::int + 1) %% 2)::boolean where name = %s and name <> %s", (user_name, login.user))
        db.commit()

    return redirect(url_for('users'))

@app.route('/edit_user/<user_name>', methods=['GET', 'POST'])
def edit_user(user_name):

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash(f'Użytkownik {login.user} nie jest adminem')
        return redirect(url_for('login'))    

    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute('select name, email from users where name = %s', [user_name])
    user = cur.fetchone()
    message = None

    if user == None:
        flash('No such user')
        return redirect(url_for('users'))

    if request.method == 'GET':
        return render_template('edit_user.html', active_menu='users', user=user, login=login)
    else:
        new_email = '' if 'email' not in request.form else request.form["email"]
        new_password = '' if 'user_pass' not in request.form else request.form['user_pass']

        if new_email != user['email']:
            sql_statement = "update users set email = %s where name = %s"
            cur.execute(sql_statement, [new_email, user_name])
            db.commit()
            flash('Email was changed')

        if new_password != '':
            user_pass = UserPass(user_name, new_password)
            sql_statement = "update users set password = %s where name = %s"
            cur.execute(sql_statement, [user_pass.hash_password(), user_name])
            db.commit()
            flash('Password was changed')

        return redirect(url_for('users'))

@app.route('/user_delete/<user_name>')
def delete_user(user_name):
    
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash(f'Użytkownik {login.user} nie jest adminem')
        return redirect(url_for('login'))   

    #if not 'user' in session:
    #    return redirect(url_for('login'))
    #login = session['user']

    db=get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    sql_statement = "delete from users where name = %s and name <> %s"
    cur.execute(sql_statement, [user_name, login.user])
    db.commit()
    return redirect(url_for('users'))

@app.route('/new_user', methods=['GET', 'POST'])
def new_user():
    
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash(f'Użytkownik {login.user} nie jest adminem')
        return redirect(url_for('login'))   

    login = session['user']
    db = get_db()
    message = None
    user = {}

    if request.method == 'GET':
        return render_template('new_user.html', active_menu='users', user=user, login=login)
    else:
        user['user_name'] = '' if not 'user_name' in request.form else request.form['user_name']
        user['email'] = '' if not 'email' in request.form else request.form['email']
        user['user_pass'] = '' if not 'user_pass' in request.form else request.form['user_pass']
        cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute('select count(*) as cnt from users where name = %s',[user['user_name']])
        record = cur.fetchone()
        is_user_name_unique = (record['cnt'] == 0)

        cur.execute('select count(*) as cnt from users where email = %s',[user['email']])
        record = cur.fetchone()
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
            sql_statement = '''insert into users(name, email, password, is_active, is_admin) values(%s,%s,%s, True, False);'''
            cur.execute(sql_statement, [user['user_name'][:100], user['email'], password_hash])
            db.commit()
            flash('User {} created'.format(user['user_name']))
            return redirect(url_for('users'))
        else:
            flash('Correct error: {}'.format(message))
            return render_template('new_user.html', active_menu='users', user=user, login=login)

@app.route('/')
def index():
    return render_template('base.html')