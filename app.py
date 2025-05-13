import time
from datetime import datetime
from flask import Flask, render_template, url_for, redirect, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ifsc'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    contacts = db.relationship('Contact', backref='owner', lazy=True)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120))
    cellphone = db.Column(db.String(20))
    photo = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_sent = db.Column(db.DateTime, nullable=False, default=datetime.now)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contact_id = db.Column(db.Integer, db.ForeignKey('contact.id'), nullable=False)
    
    sender = db.relationship('User', foreign_keys=[sender_id])
    contact = db.relationship('Contact', foreign_keys=[contact_id])

User.sent_messages = db.relationship('Message', foreign_keys=[Message.sender_id], backref='sender_ref', lazy=True)
Contact.received_messages = db.relationship('Message', foreign_keys=[Message.contact_id], backref='contact_ref', lazy=True)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, faça login para acessar esta página.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('As senhas não coincidem!', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        
        new_user = User(username=username, email=email, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Conta criada com sucesso! Agora você pode fazer login.', 'success')
            return redirect(url_for('login'))
        except:
            flash('Erro ao criar conta. Nome de usuário ou e-mail já existente.', 'danger')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('contacts'))
        else:
            flash('Login falhou. Verifique seu nome de usuário e senha.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('index'))

@app.route('/contacts')
@login_required
def contacts():
    user_contacts = Contact.query.filter_by(user_id=session['user_id']).all()
    return render_template('contacts.html', contacts=user_contacts)

@app.route('/add_contact', methods=['GET', 'POST'])
@login_required
def add_contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        cellphone = request.form['cellphone']
        
        photo_path = None
        try:
            if 'photo' in request.files:
                file = request.files['photo']
                if file and allowed_file(file.filename):
                    if not os.path.exists(app.config['UPLOAD_FOLDER']):
                        os.makedirs(app.config['UPLOAD_FOLDER'])
                    
                    filename = secure_filename(f"{session['user_id']}_{int(time.time())}_{file.filename}")
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
    
                    if os.path.exists(filepath):
                        photo_path = filename
                    else:
                        flash('Erro ao salvar a foto', 'warning')
                        photo_path = None
        except Exception as e:
            app.logger.error(f"Erro no upload: {str(e)}")
            photo_path = None
        
        new_contact = Contact(
            name=name, 
            email=email, 
            cellphone=cellphone, 
            user_id=session['user_id'],
            photo=photo_path
        )
        
        try:
            db.session.add(new_contact)
            db.session.commit()
            flash('Contato adicionado com sucesso!', 'success')
            return redirect(url_for('contacts'))
        except:
            flash('Erro ao adicionar contato.', 'danger')
    
    return render_template('add_contact.html')

@app.route('/delete_contact/<int:contact_id>')
@login_required
def delete_contact(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    
    if contact.user_id != session['user_id']:
        flash('Você não tem permissão para excluir este contato.', 'danger')
        return redirect(url_for('contacts'))
    
    try:
        db.session.delete(contact)
        db.session.commit()
        flash('Contato excluído com sucesso!', 'success')
    except:
        flash('Erro ao excluir contato.', 'danger')
    
    return redirect(url_for('contacts'))

@app.route('/send_message/<int:contact_id>', methods=['GET', 'POST'])
@login_required
def send_message(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    
    if contact.user_id != session['user_id']:
        flash('Você não pode enviar mensagens para este contato.', 'danger')
        return redirect(url_for('contacts'))
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        new_message = Message(
            title=title,
            content=content,
            sender_id=session['user_id'],
            contact_id=contact.id
        )
        
        try:
            db.session.add(new_message)
            db.session.commit()
            flash('Mensagem enviada com sucesso!', 'success')
            return redirect(url_for('view_messages', contact_id=contact.id))
        except:
            flash('Erro ao enviar mensagem.', 'danger')
    
    return render_template('send_message.html', contact=contact)

@app.route('/messages/<int:contact_id>')
@login_required
def view_messages(contact_id):
    contact = Contact.query.get_or_404(contact_id)
    
    if contact.user_id != session['user_id']:
        flash('Você não tem permissão para ver estas mensagens.', 'danger')
        return redirect(url_for('contacts'))
    
    messages = Message.query.filter(
        ((Message.sender_id == session['user_id']) & (Message.contact_id == contact_id)) |
        ((Message.sender_id == contact_id) & (Message.contact_id == session['user_id']))
    ).order_by(Message.date_sent.desc()).all()
    
    return render_template('messages.html', contact=contact, messages=messages)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)