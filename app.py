from hack import app, create_db, db
from flask import render_template, redirect, url_for
from flask_login import current_user, login_user, logout_user, login_required
from hack.forms import LoginForm, RegForm
from hack.models import User, Message
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room
from cryptography.fernet import Fernet

socketio = SocketIO(app)
create_db(app)
key = Fernet.generate_key()
f = Fernet(key)

@app.route('/')
def home():
    # for i in Message.query.all():
    #     db.session.delete(i)
    #     db.session.commit()
    return render_template('index.html')

@app.route('/reg', methods=['GET', 'POST'])
def reg():
    form = RegForm()
    mess = ''
    if form.validate_on_submit():
        email = form.email.data
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            mess = 'Account already exists'
        else:
            new_user = User(email=email, username=username,
                            password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect('/')
    return render_template('reg.html', form=form, mess=mess)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    mess = ''
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if not user:
            mess = 'Email not found'
        else:
            if check_password_hash(user.password, password):
                login_user(user, remember=True)
                return redirect(url_for('home'))
            else:
                mess = 'Incorrect password.'
    return render_template('login.html', mess=mess, form=form)

@app.route('/messages/<receiver_id>')
@login_required
def msg(receiver_id):
    print(f"Sender ID: {current_user.id}")
    print(f"Receiver ID: {receiver_id}")
    users = User.query.all()
    users.remove(current_user)

    messages = Message.query.filter(
        db.or_(
            db.and_(Message.sender_id == current_user.id,
                    Message.receiver_id == receiver_id),
            db.and_(Message.sender_id == receiver_id,
                    Message.receiver_id == current_user.id)
        )
    ).order_by(Message.timestamp.asc()).all()

    decrypted_messages = []
    for message in messages:
        decrypted_text = f.decrypt(message.encrypted_content.encode()).decode()
        decrypted_messages.append((message.sender.username, decrypted_text))
        print(decrypted_messages)
    return render_template('messages.html', receiver_id=receiver_id, decrypted_messages=decrypted_messages, users=users)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@socketio.on('connect')
def handle_connect():
    print('A user connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('A user disconnected')

@app.route('/messages')
@login_required
def dashboard():
    users = User.query.all()
    users.remove(current_user)
    if len(users) == 0:
        return redirect('/')
    return redirect(url_for('msg', receiver_id=users[0].id))

@socketio.on('message')
def handle_message(data):
    print(data)
    sender_user = User.query.get(current_user.id)
    receiver_user = User.query.get(data['receiver_id'])
    encrypted_content = f.encrypt(data['message'].encode()).decode()

    msg = Message(
        encrypted_content=encrypted_content,
        sender=sender_user,
        receiver=receiver_user
    )
    db.session.add(msg)
    db.session.commit()

    room = 'user_' + data['receiver_id']
    join_room(room=room)

    decrypted_content = f.decrypt(encrypted_content.encode()).decode()

    emit('message', {
        'sender': current_user.username,
        'message': decrypted_content,
        'receiver_id': data['receiver_id']
    }, room=room)

if __name__ == '__main__':
    socketio.run(app, debug=True)
