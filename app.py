from flask import Flask, render_template, request, g, redirect, url_for, flash, session, send_from_directory
import psycopg2
import hashlib
import binascii
import random
import string
import psycopg2.extras
import time
import os
from werkzeug.utils import secure_filename

app = Flask(__name__, template_folder='Templates')

if __name__ == "__main__":
    app.run(host='0.0.0.0')

UPLOAD_FOLDER = 'D:\dump'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

def get_db():
    if not hasattr(g, 'db'):
        dbname = 'workflow'
        user = 'workflow'
        password = 'workflow'
        host = 'localhost'
        port = '5432'
        conn = psycopg2.connect(dbname=dbname, user=user, password=password, host=host, port=port)
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()

#zaznaczone funckje pochodzą częściwo z poradnika Python Flask - aplikacje webowe - kurs z podręcznikiem PDF autorstwa Rafał Mobilo dostępnego pod linkiem https://www.udemy.com/course/python-flask-aplikacje-webowe/

@app.route('/init_app') #funckja częściwo zaczerpnięta z prodnika
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
    username = user_pass.user[:100]  # truncate the name to 100 characters
    email = 'admin@admin.notmail'
    password = user_pass.hash_password()
    sql_statement = "INSERT INTO users (username, email, password, is_active, is_admin, is_cyber) VALUES (%s, %s, %s, %s, %s, %s)"
    cur.execute(sql_statement, [username, email, password, True, True, False])
    db.commit()
    flash('User {} with password {} has been created'.format(user_pass.user, user_pass.password))
    return redirect(url_for('index'))

@app.route('/login', methods=['GET','POST']) #funckja częściwo zaczerpnięta z prodnika
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

@app.route('/logout') #funckja częściwo zaczerpnięta z prodnika
def logout(): #funckja częściwo zaczerpnięta z prodnika

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
        self.is_cyber = False

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
        random_user = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))
        self.user = random_user

        password_characters = string.ascii_letters  # + string.digits + string.punctuation
        random_password = ''.join(random.choice(password_characters) for _ in range(20))
        self.password = random_password
    
    def login_user(self):
        db = get_db()
        sql_statement = 'select id_use, username, email, password, is_active, is_admin from users where username=%s'
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
        sql_statement = 'select username, email, is_active, is_admin, is_cyber from users where username=%s'
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
            self.is_cyber = db_user['is_cyber']
            self.email = db_user['email']       

@app.route('/users') #funckja częściwo zaczerpnięta z prodnika
def users():

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        flash(f'Użytkownik {login.user} nie aktywny')
        return redirect(url_for('login'))


    db = get_db()
    sql_command = 'select id_use, username, email, is_admin, is_active, is_cyber from users;'
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(sql_command)
    users=cur.fetchall()

    return render_template('users.html', active_menu='users', users=users, login=login)

@app.route('/user_status_change/<action>/<user_name>') #funckja częściwo zaczerpnięta z prodnika
def user_status_change(action, user_name):

    # app.py – code to add to functions – admin access

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash(f'Użytkownik {login.user} nie jest adminem')
        return redirect(url_for('login'))

    db = get_db()

    if action == 'active':
        cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        #tatus_sql='select is_active from users where name='aaa';'
        cur.execute("update users set is_active = ((is_active::int + 1) %% 2)::boolean where username = %s and username <> %s ", (user_name, login.user))       
        db.commit()
    elif action == 'admin':
        cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("update users set is_admin = ((is_admin::int + 1) %% 2)::boolean where username = %s and username <> %s", (user_name, login.user))
        db.commit()

    return redirect(url_for('users'))

@app.route('/edit_user/<user_name>', methods=['GET', 'POST']) #funckja częściwo zaczerpnięta z prodnika
def edit_user(user_name):

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash(f'Użytkownik {login.user} nie jest adminem')
        return redirect(url_for('login'))    

    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute('select username, email from users where username = %s', [user_name])
    user = cur.fetchone()

    if user == None:
        flash('No such user')
        return redirect(url_for('users'))

    if request.method == 'GET':
        return render_template('edit_user.html', active_menu='users', user=user, login=login)
    else:
        new_email = '' if 'email' not in request.form else request.form["email"]
        new_password = '' if 'user_pass' not in request.form else request.form['user_pass']

        if new_email != user['email']:
            sql_statement = "update users set email = %s where username = %s"
            cur.execute(sql_statement, [new_email, user_name])
            db.commit()
            flash('Email was changed')

        if new_password != '':
            user_pass = UserPass(user_name, new_password)
            sql_statement = "update users set password = %s where username = %s"
            cur.execute(sql_statement, [user_pass.hash_password(), user_name])
            db.commit()
            flash('Password was changed')

        return redirect(url_for('users'))
    
@app.route('/self_edit_user', methods=['GET', 'POST'])
def self_edit_user():

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        flash(f'Użytkownik {login.user} nie aktywny')
        return redirect(url_for('login'))

    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute('select username, email from users where username = %s', [login.user])
    user = cur.fetchone()

    if request.method == 'GET':
        return render_template('self_edit_user.html', active_menu='users', user=user, login=login)
    else:
        new_email = '' if 'email' not in request.form else request.form["email"]
        new_password = '' if 'user_pass' not in request.form else request.form['user_pass']
        password2 = '' if 'user_pass2' not in request.form else request.form['user_pass2']

        if new_email == user['email']:          
            if new_password != '':
                if new_password == password2:
                    user_pass = UserPass(login.user, new_password)
                    sql_statement = "update users set password = %s where username = %s"
                    cur.execute(sql_statement, [user_pass.hash_password(), login.user])
                    db.commit()
                    flash('Password was changed')
                else:
                    flash('Hasła nie są takie same')           
            else:
                flash('Nie podano nowego hasła')    
        else:
            flash('Nie możesz zmienić hasła dla innego użytownika')    

        return redirect(url_for('users'))    

@app.route('/user_delete/<user_name>') #funckja częściwo zaczerpnięta z prodnika
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
    sql_statement = "delete from users where username = %s and username <> %s"
    cur.execute(sql_statement, [user_name, login.user])
    db.commit()
    return redirect(url_for('users'))

@app.route('/new_user', methods=['GET', 'POST']) #funckja częściwo zaczerpnięta z prodnika
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
        cur.execute('select count(*) as cnt from users where username = %s',[user['user_name']])
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
            sql_statement = '''insert into users(username, email, password, is_active, is_admin) values(%s,%s,%s, True, False);'''
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


@app.route('/main')
def main():
    return render_template('base.html')

@app.route('/admin_menu')
def admin_menu():
    return render_template('base.html')

@app.route('/admin_docks')
def admin_docks():
    return render_template('base.html')

@app.route('/admin_edit_user')
def admin_edit_user():
    return render_template('base.html')

@app.route('/admin_settings')
def admin_settings():
    return render_template('base.html')

@app.route('/admin_upload')
def admin_upload():
    return render_template('base.html')

@app.route('/upload')
def upload():
    return render_template('base.html')

@app.route('/settings')
def settings():
    return render_template('base.html')

@app.route('/docks')
def docks():
    return render_template('base.html')

@app.route('/workflows', methods=['GET', 'POST'])
def workflows():
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash(f'Użytkownik {login.user} nie jest adminem')
        return redirect(url_for('login'))
    
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    sql_command = '''
WITH RankedApproval AS (
    SELECT
        f.flowname,
        f.flowdescription,
        fl.filename,
        g.groupname,
        f.status,
        at.flow_id,
        at.group_id,
        at.value,
        f.number,
        at.description,
        ROW_NUMBER() OVER (PARTITION BY f.id_flo ORDER BY at.value) AS rn
    FROM
        public.flow f
    INNER JOIN
        public.files fl ON f.file_id = fl.id_fil
    INNER JOIN
        public.approval_table at ON f.id_flo = at.flow_id
    INNER JOIN
        public.group_members gm ON at.group_id = gm.group_id
    INNER JOIN
        public.users u ON gm.user_id = u.id_use
    INNER JOIN
        public.groups g ON gm.group_id = g.id_grp
    WHERE
        f.status = FALSE
)
SELECT
    flowname,
    flowdescription,
    filename,
    groupname,
    status,
    flow_id,
    group_id,
    value,
    number,
    description
FROM
    RankedApproval
WHERE
    rn = 1;

'''
    
    cur.execute(sql_command)

    false_flows=cur.fetchall()

    sql_command2 = '''
WITH RankedApproval AS (
    SELECT
        f.flowname,
        f.flowdescription,
        fl.filename,
        g.groupname,
        f.status,
        at.flow_id,
        at.group_id,
        at.value,
        f.number,
        at.description,
        ROW_NUMBER() OVER (PARTITION BY f.id_flo ORDER BY at.value) AS rn
    FROM
        public.flow f
    INNER JOIN
        public.files fl ON f.file_id = fl.id_fil
    INNER JOIN
        public.approval_table at ON f.id_flo = at.flow_id
    INNER JOIN
        public.group_members gm ON at.group_id = gm.group_id
    INNER JOIN
        public.users u ON gm.user_id = u.id_use
    INNER JOIN
        public.groups g ON gm.group_id = g.id_grp
    WHERE
        f.status = TRUE
)
SELECT
    flowname,
    flowdescription,
    filename,
    groupname,
    status,
    flow_id,
    group_id,
    value,
    number,
    description
FROM
    RankedApproval
WHERE
    rn = 1;
'''
    cur2 = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur2.execute(sql_command2)

    true_flows=cur2.fetchall()

    return render_template('flows.html', active_menu='users', true_flows=true_flows, login=login, false_flows=false_flows)


@app.route('/flow_info/<id_flo>', methods=['GET', 'POST']) 
def flow_info(id_flo):
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
       flash(f'Użytkownik {login.user} nie aktywny')
       return redirect(url_for('login'))


    db = get_db()
    sql_command = 'SELECT f.id_flo, f.flowname, f.flowdescription, fl.filename AS file_name, f.number, f.status FROM flow f INNER JOIN files fl ON f.file_id = fl.id_fil;'
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(sql_command)
    flows=cur.fetchall() 
    
    #sql_command2 = 'SELECT id_app, flow_id, group_id, value FROM approval_table;'
    sql_command2 = 'SELECT g.groupname, at.value, at.description FROM public.flow f JOIN public.approval_table at ON f.id_flo = at.flow_id JOIN public.groups g ON at.group_id = g.id_grp WHERE f.id_flo = %s ORDER BY at.value ASC;'
    
    cur2 = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur2.execute(sql_command2,[id_flo])
    approvals=cur2.fetchall() 

    return render_template('flows_info.html', active_menu='users', flows=flows, login=login, approvals=approvals)

@app.route('/workflows_info/<id_flo>', methods=['GET', 'POST']) #do naprawy
def workflows_info(id_flo):
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
       flash(f'Użytkownik {login.user} nie aktywny')
       return redirect(url_for('login'))


    db = get_db()
    sql_command = 'SELECT f.id_flo, f.flowname, f.flowdescription, fl.filename AS file_name, f.number, f.status FROM flow f INNER JOIN files fl ON f.file_id = fl.id_fil;'
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(sql_command)
    flows=cur.fetchall() 
    
    #sql_command2 = 'SELECT id_app, flow_id, group_id, value FROM approval_table;'
    sql_command2 = 'SELECT g.groupname, at.value, at.description FROM public.flow f JOIN public.approval_table at ON f.id_flo = at.flow_id JOIN public.groups g ON at.group_id = g.id_grp WHERE f.id_flo = %s ORDER BY at.value ASC;'
    
    cur2 = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur2.execute(sql_command2,[id_flo])
    approvals=cur2.fetchall() 

    return render_template('flows_info.html', active_menu='users', flows=flows, login=login, approvals=approvals)


@app.route('/add_flow', methods=['GET', 'POST'])
def add_flow():
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        flash(f'Użytkownik {login.user} nie aktywny')
        return redirect(url_for('login'))

    #login = session['user']
    db = get_db()
    message = None
    flow = {}

    if request.method == 'GET':
        
        sql_command = 'SELECT id_fil, filename FROM files;'
        cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute(sql_command)
        files=cur.fetchall() 
        
        return render_template('new_flow.html', active_menu='new_flow', flow=flow, login=login, files=files)
    else:
        flow['flow_name'] = '' if not 'flow_name' in request.form else request.form['flow_name']
        flow['flowdescription'] = '' if not 'flowdescription' in request.form else request.form['flowdescription']
        flow['filename'] = '' if not 'filename' in request.form else request.form['filename']
        cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
                
        if flow['flow_name'] == '':
            message = 'flow_name cannot be empty'
        elif flow['flowdescription'] == '':
            message = 'flowdescription cannot be empty'
        elif flow['filename'] == '':
            message = 'filename cannot be empty'    
    
        if not message:
            sql_statement = '''INSERT INTO flow (flowname, flowdescription, file_id, number, status) VALUES  ( %s, %s, ( SELECT f.id_fil FROM public.files f WHERE f.filename = %s LIMIT 1), 0, FALSE );'''
            cur.execute(sql_statement, [ flow['flow_name'], flow['flowdescription'], flow['filename'] ])    
            db.commit()
            flash('Flow {} created'.format(flow['flow_name']))

            return redirect(url_for('workflows'))
        else:
            flash('Correct error: {}'.format(message))
            return render_template('new_flow.html', active_menu='workflows', flow=flow, login=login)
        
@app.route('/groups', methods=['GET', 'POST'])
def groups():
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
       flash(f'Użytkownik {login.user} nie aktywny')
       return redirect(url_for('login'))


    db = get_db()
    sql_command = 'SELECT * FROM groups;'
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(sql_command)
    groups=cur.fetchall() 

    return render_template('groups.html', active_menu='groups', login=login, groups=groups)

@app.route('/groups/info/<id_grp>', methods=['GET', 'POST'])
def grp_info(id_grp):
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
       flash(f'Użytkownik {login.user} nie aktywny')
       return redirect(url_for('login'))


    db = get_db()
    sql_command = 'SELECT * FROM groups;'
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(sql_command)
    groups=cur.fetchall() 
    
    #sql_command2 = 'SELECT id_app, flow_id, group_id, value FROM approval_table;'
    sql_command2 = 'SELECT id_gro, g.groupname, u.username, u.email FROM group_members gm JOIN users u ON gm.user_id = u.id_use JOIN groups g ON gm.group_id = g.id_grp WHERE g.id_grp = %s ORDER BY g.groupname, u.username;'
    
    cur2 = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur2.execute(sql_command2,[id_grp])
    members=cur2.fetchall() 

    return render_template('groups_info.html', active_menu='groups', login=login, groups=groups, members=members)

@app.route('/add_grp', methods=['GET', 'POST'])
def add_grp():
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        flash(f'Użytkownik {login.user} nie aktywny')
        return redirect(url_for('login'))
    
    db = get_db()
    message = None
    grp = {}

    if request.method == 'GET':
        return render_template('new_grp.html', active_menu='new_grp', grp=grp, login=login)
    else:
        grp['group_name'] = '' if not 'group_name' in request.form else request.form['group_name']
        grp['group_description'] = '' if not 'group_description' in request.form else request.form['group_description']
        cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
        if grp['group_name'] == '':
            message = 'group_name cannot be empty'
        elif grp['group_description'] == '':
            message = 'group_description cannot be empty'    
    
        if not message:
            sql_statement = '''INSERT INTO groups ( groupname, groupdescription) VALUES(%s,%s);'''
            cur.execute(sql_statement, [ grp['group_name'], grp['group_description'] ]) #jedne do zmiany na id usera
            db.commit()
            flash('Created {} group'.format(grp['group_name']))
            return redirect(url_for('groups'))
        
        else:
            flash('Correct error: {}'.format(message))
            return render_template('new_grp.html', active_menu='groups', grp=grp, login=login)
        
@app.route('/add_group_member/', methods=['GET', 'POST'])
def add_group_member():

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash(f'Użytkownik {login.user} nie jest adminem')
        return redirect(url_for('login'))    

    db = get_db()
    message = None
    mem = {}

    if request.method == 'GET':
        
        sql_command = 'SELECT id_use, email FROM users;'
        cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute(sql_command)
        users=cur.fetchall() 
        
        sql_command2 = 'select groupname, id_grp from groups;'
        cur2 = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur2.execute(sql_command2)
        groups=cur2.fetchall() 
    
        return render_template('add_grp_mem.html', active_menu='add_grp_mem', mem=mem, login=login, users=users, groups=groups)
    else: 
        mem['email'] = '' if not 'email' in request.form else request.form['email']
        mem['groupname'] = '' if not 'groupname' in request.form else request.form['groupname']
        cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
        cur.execute('select count(*) as cnt from users where email = %s',[mem['email']])
        record = cur.fetchone()
        is_email_walid = (record['cnt'] == 1)

        cur.execute('select count(*) as cnt from groups where groupname = %s',[mem['groupname']])
        record = cur.fetchone()
        is_group_walid = (record['cnt'] == 1) 

        if mem['email'] == '':
            message = 'user id cannot be empty'  
        elif mem['groupname'] == '':
            message = 'group id cannot be empty'
        elif not is_email_walid:
            message = 'Nie ma usera o nazawie {} w bazie danych'.format(mem['email'])
        elif not is_group_walid:
            message = 'Nie ma grupy o nazwie {} w bazie danych'.format(mem['groupname'])     

        if not message:
            sql_statement = '''INSERT INTO "group_members" ("user_id", "group_id") VALUES ( (SELECT "id_use" FROM "users" WHERE "email" = %s), (SELECT "id_grp" FROM "groups" WHERE "groupname" = %s)); '''
            cur.execute(sql_statement, [ mem['email'], mem['groupname'] ]) 
            db.commit()
            flash('Dodano uzytkownika do {} do grupy'.format(mem['email']))
            return redirect(url_for('groups'))        
        else:
            flash('Correct error: {}'.format(message))
            return render_template('add_grp_mem.html', active_menu='add_grp_mem', mem=mem, login=login)
        
@app.route('/delete_group_member/<id_gro>')
def delete_group_member(id_gro):
    
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash(f'Użytkownik {login.user} nie jest adminem')
        return redirect(url_for('login'))   

    db=get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    sql_statement = "delete from group_members where id_gro = %s"
    cur.execute(sql_statement, [id_gro])
    db.commit()
    return redirect(url_for('groups'))

@app.route('/add_group_flow/', methods=['GET', 'POST'])
def add_group_flow():

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash(f'Użytkownik {login.user} nie jest adminem')
        return redirect(url_for('login'))    

    db = get_db()
    message = None
    grop_add = {}
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if request.method == 'GET':
        
        sql_command = 'SELECT id_grp, groupname FROM groups;'
        cur.execute(sql_command)
        groups=cur.fetchall()

        sql_command = 'SELECT id_flo, flowname FROM flow;'
        cur.execute(sql_command)
        flows=cur.fetchall()  
        
        return render_template('add_grp_flow.html', active_menu='add_grp_flow', flows=flows, login=login, groups=groups)
    else: 
        grop_add['flow_id'] = '' if not 'flow_id' in request.form else request.form['flow_id']
        grop_add['group_id'] = '' if not 'group_id' in request.form else request.form['group_id']
        grop_add['value'] = '' if not 'value' in request.form else request.form['value']
    
        if grop_add['flow_id'] == '':
            message = 'flow is cannot be empty'  
        elif grop_add['group_id'] == '':
            message = 'group id cannot be empty'
        elif grop_add['value'] == '':
            message = 'value id cannot be empty'     #trzeba sprawdzic czy taka wrtosc jest wolna dla danego flow       
    
        if not message:
            sql_statement = '''
    INSERT INTO approval_table (flow_id, group_id, value) 
    SELECT f.id_flo, g.id_grp, %s 
    FROM public.flow f 
    JOIN public.groups g ON f.flowname = %s 
    WHERE g.groupname = %s 
    AND NOT EXISTS (
        SELECT 1 FROM public.approval_table at 
        WHERE at.flow_id = f.id_flo AND at.group_id = g.id_grp
    );
'''
            cur.execute(sql_statement, [ grop_add['value'], grop_add['flow_id'], grop_add['group_id'] ]) 
            db.commit()
            flash('Add group {} to flow'.format(grop_add['group_id']))
            return redirect(url_for('workflows'))
        
        else:
            flash('Correct error: {}'.format(message))
            return render_template('add_grp_flow.html', active_menu='add_grp_mem', grop_add=grop_add, login=login)


@app.route('/new_bugs', methods=['GET', 'POST'])
def new_bugs():
    #możliwe błedy z logowaniem
    db = get_db()
    message = None
    bug = {}

    if request.method == 'GET':
        return render_template('new_bugs.html', active_menu='new_bugs', bug=bug, login=login)
    else:
        bug['name'] = '' if not 'name' in request.form else request.form['name']
        bug['error_description'] = '' if not 'error_description' in request.form else request.form['error_description']

        cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        if bug['name'] == '':
            message = 'name cannot be empty'
        elif bug['error_description'] == '':
            message = 'error_description cannot be empty'

        if not message:
            sql_statement = '''INSERT INTO bugs (name ,description) VALUES(%s,%s);'''
            cur.execute(sql_statement, [bug['name'], bug['error_description']])
            db.commit()
            flash('Bug {} upolded'.format(bug))

            return redirect(url_for('main'))
        else:
            flash('Correct error: {}'.format(message))
            return render_template('new_bugs.html', active_menu='new_bugs', bug=bug, login=login)
        
@app.route('/admin_bugs')
def admin_bugs():

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not (login.is_admin or login.is_cyber):
        flash(f'Użytkownik {login.user} nie jest adminem bądź oficerem bezpieczenstwa')
        return redirect(url_for('login')) 


    db = get_db()
    sql_command = 'select id_bug, name, description from bugs;'
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(sql_command)
    bugs=cur.fetchall()

    return render_template('admin_bugs.html', active_menu='users', bugs=bugs, login=login)

@app.route('/bug_delete/<id_bug>')
def bug_delete(id_bug):
    
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_cyber:
        flash(f'Użytkownik {login.user} nie jest oficerem bezpieczenstawa')
        return redirect(url_for('login'))   

    db=get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    sql_statement = "delete from bugs where id_bug = %s"
    cur.execute(sql_statement, [id_bug])
    db.commit()
    return redirect(url_for('admin_bugs'))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    

@app.route('/uploads/<name>')
def download_file(name):
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)

@app.route('/uploads_secret/<name>')
def download_secret_file(name):

    db = get_db()
    sql_statement = 'select filepath from files where filename=%s;'
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(sql_statement, [name])
    result = cur.fetchone()

    if result is not None:
        file_path = result[0]
        return download_file(file_path)
    else:
        return "File not found", 404


@app.route('/add_file', methods=['GET', 'POST'])
def add_file():
    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        flash(f'Użytkownik {login.user} nie aktywny')
        return redirect(url_for('login'))

    db = get_db()
    message = None
    data = {}

    if request.method == 'GET':
        return render_template('add_file.html', active_menu='new_file', data=data, login=login)
    else:
        data['publicfilename'] = '' if not 'publicfilename' in request.form else request.form['publicfilename']

        cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute('select count(*) as cnt from files where filename = %s',[data['publicfilename']])
        record = cur.fetchone()
        is_filename_unique = (record['cnt'] == 0)

        if data['publicfilename'] == '':
            message = 'publicfilename cannot be empty'
        elif not is_filename_unique:
            message = 'file name {} już taki jest'.format(data['publicfilename'])    

        if not message:
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']

            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                secretfilename = str(time.time()+14123)+filename #randrange(10)  trzeba polosować raczej
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], secretfilename))


                cur.execute('SELECT id_use FROM users where username=%s',[login.user])
                result = cur.fetchone()
                if result is not None:
                    user_id = result[0]
                
                sql_statement2 = '''INSERT INTO files (filename, filepath, uploder) VALUES(%s,%s,%s);'''
                cur.execute(sql_statement2,[ data['publicfilename'], secretfilename, user_id ])
                db.commit()
                flash('Plik {} upolded'.format(file))
                #return redirect(url_for('download_file', name=filename))
            return redirect(url_for('main'))
        else:
            flash('Correct error: {}'.format(message))
            return render_template('add_file.html', active_menu='new_file', data=data, login=login)

@app.route('/files')
def files():

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid or not login.is_admin:
        flash(f'Użytkownik {login.user} nie jest adminem')
        return redirect(url_for('login'))   


    db = get_db()
    sql_command = 'select filename, filepath, username from files INNER JOIN users ON users.id_use = files.uploder;'
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(sql_command)
    files=cur.fetchall()

    return render_template('files.html', files=files, login=login)


@app.route('/my_aprove')
def my_aprove():

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        flash(f'Użytkownik {login.user} nie aktywny')
        return redirect(url_for('login'))

  

    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute('SELECT id_use FROM users where username=%s',[login.user])
    result = cur.fetchone()
    if result is not None:
        user_id = result[0]  

    sql_command = '''
    WITH RankedApproval AS (
    SELECT
        f.flowname,
        f.flowdescription,
        fl.filename,
        g.groupname,
        f.status,
        at.flow_id,
        at.group_id,
        at.value,
        f.number,
        at.description,
        ROW_NUMBER() OVER (PARTITION BY f.id_flo ORDER BY at.value) AS rn
    FROM
        public.flow f
    INNER JOIN
        public.files fl ON f.file_id = fl.id_fil
    INNER JOIN
        public.approval_table at ON f.id_flo = at.flow_id
    INNER JOIN
        public.group_members gm ON at.group_id = gm.group_id
    INNER JOIN
        public.users u ON gm.user_id = u.id_use
    INNER JOIN
        public.groups g ON gm.group_id = g.id_grp
    WHERE
        f.status = FALSE
        AND u.id_use = %s
)
SELECT
    flowname,
    flowdescription,
    filename,
    groupname,
    status,
    flow_id,
    group_id,
    value,
    number,
    description
FROM
    RankedApproval
WHERE
    rn = 1;
'''
    
    cur.execute(sql_command, [user_id])

    false_flows=cur.fetchall()

    sql_command = '''
    WITH RankedApproval AS (
    SELECT
        f.flowname,
        f.flowdescription,
        fl.filename,
        g.groupname,
        f.status,
        at.flow_id,
        at.group_id,
        at.value,
        f.number,
        at.description,
        ROW_NUMBER() OVER (PARTITION BY f.id_flo ORDER BY at.value) AS rn
    FROM
        public.flow f
    INNER JOIN
        public.files fl ON f.file_id = fl.id_fil
    INNER JOIN
        public.approval_table at ON f.id_flo = at.flow_id
    INNER JOIN
        public.group_members gm ON at.group_id = gm.group_id
    INNER JOIN
        public.users u ON gm.user_id = u.id_use
    INNER JOIN
        public.groups g ON gm.group_id = g.id_grp
    WHERE
        f.status = TRUE
        AND u.id_use = %s
)
SELECT
    flowname,
    flowdescription,
    filename,
    groupname,
    status,
    flow_id,
    group_id,
    value,
    number,
    description
FROM
    RankedApproval
WHERE
    rn = 1;
'''
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(sql_command, [user_id])

    true_flows=cur.fetchall()

    return render_template('my_flows.html', false_flows=false_flows, login=login, true_flows=true_flows) 

@app.route('/aprove/<id_flo>', methods=['GET', 'POST'])
def aprove(id_flo):

    login = UserPass(session.get('user'))
    login.get_user_info()
    if not login.is_valid:
        flash(f'Użytkownik {login.user} nie aktywny')
        return redirect(url_for('login'))

    db = get_db()
    message = None
    action = {}
    cur = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute('SELECT id_use FROM users where username=%s',[login.user])
    result = cur.fetchone()
    if result is not None:
        user_id = result[0]

    #cur.execute(sql_command,[id_flo])
    #infos=cur.fetchall() 


    if request.method == 'GET':
        sql_command = 'SELECT f.id_flo, f.flowname, f.flowdescription, fl.filename AS file_name, f.number, f.status FROM flow f INNER JOIN files fl ON f.file_id = fl.id_fil where fl.id_fil=%s;'
        cur.execute(sql_command,[id_flo])
        flows=cur.fetchall() 
        
        #sql_command2 = 'SELECT id_app, flow_id, group_id, value FROM approval_table;'
        sql_command2 = 'SELECT g.groupname, at.value, at.description FROM public.flow f JOIN public.approval_table at ON f.id_flo = at.flow_id JOIN public.groups g ON at.group_id = g.id_grp WHERE f.id_flo = %s ORDER BY at.value ASC;'
        
        
        cur.execute(sql_command2,[id_flo])
        approvals=cur.fetchall() 

        return render_template('flows_info_new.html', active_menu='users', flows=flows, login=login, approvals=approvals, action=action)
    else:
        action['komentarz'] = '' if not 'komentarz' in request.form else request.form['komentarz']
        action['opcja'] = '' if not 'opcja' in request.form else request.form['opcja']
        #option = request.form['options']

        
        if action['opcja'] == '':
            message = 'opcja cannot be empty'

        
        
        if not message:
            sql_statement1 = 'SELECT at.id_app number FROM public.flow f JOIN public.approval_table at ON f.id_flo = at.flow_id JOIN public.groups g ON at.group_id = g.id_grp WHERE f.id_flo = 2 and at.value=number ORDER BY at.value ASC ;'
            cur.execute(sql_statement1, [id_flo])
            id_app=result = cur.fetchone()

            if action['opcja']=='Akceptacja':
                sql_statement2 = '''SELECT
                MIN(at.value) AS next_min_greater_value
                FROM
                    public.flow f
                JOIN
                    public.approval_table at ON f.id_flo = at.flow_id
                JOIN
                    public.groups g ON at.group_id = g.id_grp
                WHERE
                    f.id_flo = %s
                    AND at.value > f.number
                GROUP BY
                    g.groupname, at.description

                '''
                cur.execute(sql_statement2, [id_flo])
                idki=result = cur.fetchone()
                
                if idki is None:
                # Execute SQL statement when idki is None
                    sql_statement1 = 'UPDATE approval_table SET description = %s WHERE id_app = %s;'
                    cur.execute(sql_statement1, [action['komentarz'],id_app[0]])
                    db.commit()
                    sql_statement2 = 'UPDATE public.flow SET status = TRUE WHERE id_flo = %s;'
                    cur.execute(sql_statement2, [id_flo])
                    db.commit()
                else:
                    sql_statement1 = 'UPDATE approval_table SET description = %s WHERE id_app = %s;'
                    cur.execute(sql_statement1, [action['komentarz'],id_app[0]])
                    db.commit()
                    sql_statement2 = 'UPDATE flow SET number = %s WHERE id_flo = %s;'
                    cur.execute(sql_statement2,[idki[0], id_flo] )
                    db.commit()
            else:
                sql_statement1 = 'UPDATE approval_table SET description = %s WHERE id_app = %s;'
                cur.execute(sql_statement1, [action['komentarz'],id_app[0]])
                db.commit()
                sql_statement2 = 'UPDATE flow SET status = TRUE WHERE id_flo = %s;'
                cur.execute(sql_statement2, [id_flo])
                db.commit()
            
            #db.commit()
            flash('Dokonano {} update'.format(action))

            return redirect(url_for('main'))
        else:
            flash('Correct error: {}'.format(message))
            return render_template('new_bugs.html', active_menu='new_bugs', action=action, login=login)
