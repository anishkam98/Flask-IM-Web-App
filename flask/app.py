import bcrypt
from classes import User
from file import db
from flask import Flask, render_template, request, redirect, url_for, session, send_file, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_mysqldb import MySQL
from flask_socketio import SocketIO, join_room, leave_room
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
import json
from markupsafe import escape
import MySQLdb.cursors
from password_strength import PasswordPolicy


app = Flask(__name__)


# Database config and app setup
db(app)
# Initialize MySQL
mysql = MySQL(app)
app.config["SESSION_TYPE"] = "filesystem"
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True
app.jinja_options["autoescape"] = lambda _: True
Session(app)
csrf = CSRFProtect(app)
socketio = SocketIO(app, manage_session=False)
login_manager = LoginManager()
login_manager.init_app(app)

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

@app.after_request
def apply_caching(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["HTTP-HEADER"] = "VALUE"
    return response

@login_manager.user_loader
def load_user(user_id):
    print("user" in session and session["user"].get_id() == user_id)
    print(user_id)
    print(session["user"].get_id())
    return session["user"] if "user" in session and str(session["user"].get_id()) == str(user_id) else None

@app.login_manager.unauthorized_handler
def unauth_handler():
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
def login():
    errorMessage = ''
    if request.method == 'POST':
        identity = request.form['email']
        password = request.form['password'].encode('utf-8')
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        # Check if this user exist
        checkusers = cursor.execute('SELECT user_id, username, email, first_name, last_name, password FROM tb_users WHERE (username = %s OR email = %s)', ([identity, identity]))
        if checkusers:
            account = cursor.fetchone()
            # Compare the hash values of the passwords
            hashed_password = account["password"].encode('utf-8')
            if bcrypt.checkpw(password, hashed_password):
                # Create object and appropriate session data
                #session["loggedin"] = True
                authenticatedUser = User(account['user_id'], account['username'], account['first_name'], account['last_name'])
                # TODO: Implement Remember Me functionality
                login_user(authenticatedUser)
                current_user.is_authenticated = True
                session["user"] = authenticatedUser
                # Change status to show that user is online
                cursor.execute('UPDATE tb_users SET is_online = 1 WHERE user_id = %s', [session['user'].userid])
                mysql.connection.commit()
                return redirect(url_for('main'))
            # If the hash values don't match
            else:
                errorMessage = ("Incorrect Username or Password.")
        # If the user doesn't exist
        else:     
            errorMessage = ("Incorrect Username or Password.")
    return render_template('login.html', errorMessage=errorMessage)

@app.route('/register', methods=['GET', 'POST'])
def register():
    errorMessage = ''
    if request.method == 'POST':
        firstname = request.form['firstname']
        middlename = request.form['middlename']
        lastname = request.form['lastname']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        # Hash the password
        passwordhash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        # Check if the email and username are already in use
        cursor.execute("SELECT user_id FROM tb_users WHERE username = %s", [username])
        checkusername = cursor.fetchall()
        cursor.execute("SELECT user_id FROM tb_users WHERE email = %s", [email])
        checkemail = cursor.fetchall()
        if checkusername:
            errorMessage = 'Please select a different username.'
        elif checkemail:
            errorMessage = 'This email is already in use.'  
        # Create the user
        else:
            if middlename:
                cursor.execute('INSERT INTO tb_users (first_name, middle_name, last_name, username, email, password, is_active, is_online) VALUES (%s, %s, %s, %s, %s, %s, 1, 0)', [firstname, middlename, lastname, username.lower(), email.lower(), passwordhash])
            else:
                cursor.execute('INSERT INTO tb_users (first_name, last_name, username, email, password, is_active, is_online) VALUES (%s, %s, %s, %s, %s, 1, 0)', [firstname, lastname, username.lower(), email.lower(), passwordhash])
            mysql.connection.commit()
            return redirect(url_for('login'))
    return render_template('register.html', errorMessage=errorMessage)
  
@app.route('/main', methods=['GET', 'POST'])
@login_required
def main():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # Get other users that are online
    cursor.execute('SELECT username, user_id FROM tb_users WHERE is_online = 1 and user_id != %s', [session['user'].userid])
    activeusers = cursor.fetchall()
    # Get existing chats
    cursor.execute('SELECT u.conversation_id, c.name FROM tb_user_conversations u INNER JOIN tb_conversations c ON u.conversation_id = c.conversation_id WHERE u.user_id = %s', [session['user'].userid])
    conversations = cursor.fetchall()
    # Create a new chat
    if request.method == 'POST':
        username = request.form['username']
        other_userid = request.form['other_userid']
        convonamedefault = str(username+', '+session['user'].username)
        cursor.execute('INSERT INTO tb_conversations (name) VALUES (%s)', [convonamedefault])
        cursor.execute('SELECT LAST_INSERT_ID() as convoid')
        convoid = cursor.fetchone()
        # Add the appropriate users to the chat
        cursor.execute('INSERT INTO tb_user_conversations (conversation_id, user_id, is_creator) VALUES (%s, %s, 1)', [convoid['convoid'], [session['user'].userid]])
        cursor.execute('INSERT INTO tb_user_conversations (conversation_id, user_id, is_creator) VALUES (%s, %s, 0)', [convoid['convoid'], other_userid])
        mysql.connection.commit()
        return redirect(url_for('chat', id=convoid['convoid']))
    return render_template('main.html', activeusers=activeusers, conversations=conversations)

@app.route('/chat-<id>', methods=['GET', 'POST'])
@login_required
def chat(id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # Get existing messages in this chat
    cursor.execute("SELECT l.log_id, u.user_id, json_extract(Log_content, '$.IM') as IM, u.username, l.created_date FROM tb_log l INNER JOIN tb_users u ON u.user_id=l.user_id  WHERE json_extract(Log_content, '$.chatid') = %s and json_extract(Log_content, '$.deleted') = \"0\" ORDER BY l.created_date", [escape(id)])
    IMs_log = cursor.fetchall()
    IMs = []
    for i in IMs_log:
        converted_im = json.loads(i['IM'])
        timestamp = i['created_date'].strftime("%d %b %Y %I:%M:%S %p")
        IMs.append({'log_id': i['log_id'], 'user_id': i['user_id'], 'IM': converted_im, 'username': i['username'], 'created_date': timestamp})
    return render_template('chat.html', id=id, IMs=IMs)

@socketio.on('join_room')
def handle_join_room_event(data):
    # Join socketio room
    room = data['chatid']
    join_room(room)
    socketio.emit('join_room_announcement', data, to=room)
    
@socketio.on('send_message')
def handle_send_message_event(data):
    # Send messages in real time using socketio
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # Create an entry in the log table when an IM is sent
    logrecord = json.dumps({'IM': data['message'], 'chatid': data['chatid'], 'deleted': "0", 'reported': "0"})
    cursor.execute("INSERT INTO tb_log (user_id, log_type, log_content) VALUES (%s, 'IM', %s)", [escape(data['userid']), logrecord])
    mysql.connection.commit()
    # Retrieve the primary key of the IM log entry
    cursor.execute("SELECT LAST_INSERT_ID() as log_id")
    log_id = cursor.fetchone()
    # Retrieve the timestamp
    cursor.execute("SELECT created_date FROM tb_log WHERE log_id = %s", [log_id['log_id']])
    t = cursor.fetchone()
    # Reformat the timestamp and add it to the data
    timestamp = t['created_date'].strftime("%d %b %Y %I:%M:%S %p")
    data.update({'timestamp': timestamp, 'log_id': log_id['log_id']})
    # Emit to all players in this chat
    socketio.emit('receive_message', data, to=data['chatid'])

@socketio.on('delete_message')
def handle_delete_message_event(data):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    logrecord = json.dumps({'type': "IM", 'log_id': data['logid']})
    # Create an entry in the log table for the deletion request
    cursor.execute("INSERT INTO tb_log (user_id, log_type, log_content) VALUES (%s, 'deletion request', %s)", [escape(data['userid']), logrecord])
    # Mark the log entry as deleted
    cursor.execute("UPDATE tb_log SET log_content = JSON_REPLACE(Log_content, '$.deleted', '1') WHERE log_id = %s", [escape(data['logid'])])
    mysql.connection.commit()
    
@socketio.on('report_message')
def handle_report_message_event(data):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    logrecord = json.dumps({'type': "IM", 'log_id': data['logid']})
    # Create an entry in the log table for the deletion request
    cursor.execute("INSERT INTO tb_log (user_id, log_type, log_content) VALUES (%s, 'report request', %s)", [escape(data['userid']), logrecord])
    # Mark the log entry as deleted
    cursor.execute("UPDATE tb_log SET log_content = JSON_REPLACE(Log_content, '$.reported', '1') WHERE log_id = %s", [escape(data['logid'])])
    mysql.connection.commit()
    
@socketio.on('leave_room')
def handle_leave_room_event(data):
    # Leave socketio room
    room = data['chatid']
    leave_room(room)
    socketio.emit('leave_room_announcement', data, room)

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # Change status to offline
    cursor.execute('UPDATE tb_users SET is_online = 0 WHERE user_id = %s', [session['user'].userid])
    mysql.connection.commit()
    # Remove session data and return to login page
    session["user"].is_authenticated = False
    current_user.is_authenticated = False
    session.clear()
    logout_user()
    return redirect(url_for('login'))
  

if __name__ == "__main__":
    socketio.run(app)