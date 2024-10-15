from flask import Flask, render_template, redirect, url_for, flash, session, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from datetime import datetime
from google.cloud import storage
import hashlib
import uuid
import firebase_admin
from firebase_admin import credentials
from cryptography.fernet import Fernet, InvalidToken
import random
from flask_socketio import SocketIO, emit, join_room, leave_room
import eventlet



app = Flask(__name__)
login_manager = LoginManager(app)
app.config['SECRET_KEY'] = 'futuroheine2024'
socketio = SocketIO(app)

# Configuração da base de dados (usando Supabase com PostgreSQL)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres.siihlnhoryxbdhrkkmie:futuroheine2024@aws-0-sa-east-1.pooler.supabase.com:6543/postgres'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
login_manager = LoginManager()
login_manager.init_app(app)

db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nome_completo = db.Column(db.String(150), nullable=False)
    data_nascimento = db.Column(db.Date, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha_hash = db.Column(db.String(128), nullable=False)
    turma_id = db.Column(db.Integer, db.ForeignKey('turma.id'), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_gremio = db.Column(db.Boolean, default=False)
    is_representante = db.Column(db.Boolean, default=False)
    foto_perfil = db.Column(db.String(255), nullable=True)

    turma = db.relationship('Turma', back_populates='alunos')
    faltas = db.relationship('Falta', back_populates='aluno')



class Menu(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    day = db.Column(db.String(20), nullable=False)
    lunch = db.Column(db.String(100), nullable=False)
    coffee = db.Column(db.String(100), nullable=False)
    first_year_time = db.Column(db.String(20), nullable=False)
    second_year_time = db.Column(db.String(20), nullable=False)
    third_year_time = db.Column(db.String(20), nullable=False)

class Turma(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(10), nullable=False)
    key = db.Column(db.String(255), nullable=True)  # Nova coluna para a chave

    def __repr__(self):
        return f'<Turma {self.nome}>'

    alunos = db.relationship('User', back_populates='turma')
    faltas = db.relationship('Falta', back_populates='turma')

class Falta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    data = db.Column(db.Date, nullable=False)
    presente = db.Column(db.Boolean, nullable=False, default=True)
    falta_justificada = db.Column(db.Boolean, nullable=False, default=False)
    turma_id = db.Column(db.Integer, db.ForeignKey('turma.id'), nullable=False)
    aluno = db.relationship('User', back_populates='faltas')
    turma = db.relationship('Turma', back_populates='faltas')

class DiaSemAula(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Date, nullable=False, unique=True)
    descricao = db.Column(db.String(255), nullable=True)

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    turma_id = db.Column(db.Integer, db.ForeignKey('turma.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mensagem = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    turma = db.relationship('Turma', back_populates='mensagens')
    user = db.relationship('User', back_populates='mensagens')

Turma.mensagens = db.relationship('ChatMessage', order_by=ChatMessage.timestamp, back_populates='turma')
User.mensagens = db.relationship('ChatMessage', order_by=ChatMessage.timestamp, back_populates='user')



def upload_foto_perfil(foto):
    if foto:
        # Criptografar o nome do arquivo
        nome_arquivo = hashlib.sha256(foto.filename.encode()).hexdigest() + '.jpg'
        
        # Configurar o cliente do Firebase Storage
        client = storage.Client()
        bucket = client.get_bucket('app-erichedu.appspot.com')

        # Fazer upload da imagem
        blob = bucket.blob(nome_arquivo)
        blob.upload_from_file(foto)

        # Retornar o caminho da imagem
        return f'gs://app-erichedu.appspot.com/{nome_arquivo}'
    
    return None


@app.route('/')
def index():
    return render_template('welcome.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.senha_hash, senha):
            login_user(user)
            session['user_id'] = user.id
            flash('Login bem-sucedido!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Email ou senha inválidos.', 'danger')
    
    return render_template('login.html')

@app.route('/admin_area')
@login_required
def admin_area():
    if not current_user.is_admin:
        flash('Acesso restrito a administradores.', 'danger')
        return redirect(url_for('index'))
    
    return render_template('admin_area.html')

@app.route('/upload_materia', methods=['POST'])
@login_required
def upload_materia():
    if not current_user.is_admin:
        flash('Apenas representantes e o grêmio podem enviar matérias.', 'danger')
        return redirect(url_for('index'))
    
    return "Matéria enviada com sucesso!"

@app.route('/home')
@login_required
def home():
    user = User.query.get(session['user_id'])
    return render_template('home.html', user=user)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logout bem-sucedido!', 'success')
    return redirect(url_for('login'))

@app.route('/quadro_almoco')
@login_required
def quadro_almoco():
    if not current_user.is_gremio:
        flash('Apenas o grêmio estudantil pode gerenciar o quadro de almoço.', 'danger')
        return redirect(url_for('index'))

    return "Quadro de almoço atualizado com sucesso!"

@app.route('/eu')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    return render_template('eu.html', user=user)

# Inicializar o Firebase Admin SDK
cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred, {
    'storageBucket': 'gs://app-erichedu.appspot.com'  # Substitua pelo seu bucket do Firebase Storage
})

# Configurações do Firebase Storage
storage_client = storage.Client.from_service_account_json("serviceAccountKey.json")
bucket = storage_client.bucket("app-erichedu.appspot.com")  # Substitua pelo nome do seu bucket do Firebase Storage

# Função de upload de imagem
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'jpg', 'jpeg', 'png'}

def save_profile_picture(picture):
    if picture and allowed_file(picture.filename):
        ext = picture.filename.rsplit('.', 1)[1].lower()
        new_filename = f"{uuid.uuid4().hex}.{ext}"
        
        blob = bucket.blob(new_filename)
        blob.upload_from_file(picture, content_type=picture.content_type)
        blob.make_public()  # Tornar a imagem pública
        return blob.public_url
    return None

# Rota para edição de perfil
@app.route('/editar_perfil', methods=['GET', 'POST'])
@login_required
def editar_perfil():
    if request.method == 'POST':
        nome = request.form.get('nome')
        senha = request.form.get('senha')
        foto_perfil = request.files.get('foto_perfil')
        
        if nome:
            current_user.nome_completo = nome
        
        if senha:
            current_user.generate_password_hash(senha)  # Assumindo que você tem um método para hash a senha
        
        if foto_perfil:
            url_foto = save_profile_picture(foto_perfil)
            if url_foto:
                current_user.foto_perfil = url_foto
        
        db.session.commit()  # Salva as alterações no banco de dados
        flash('Perfil atualizado com sucesso!', 'success')
        return redirect(url_for('editar_perfil'))

    return render_template('editar_perfil.html', user=current_user)


# Função para gerar uma chave válida para Fernet
def generate_key():
    return Fernet.generate_key()  # Retorna a chave como bytes

# Gera uma chave para a turma e a retorna como string
def generate_turma_key():
    return generate_key().decode()  # Retorna a chave como string base64

def ensure_all_turmas_have_key():
    turmas = Turma.query.all()
    for turma in turmas:
        if not turma.key:  # Verifica se a chave não existe
            turma.key = generate_turma_key()  # Gere uma chave válida para Fernet
            db.session.commit()  # Salva a chave no banco de dados

# Função para criptografar a mensagem
def encrypt_message(message, key):
    f = Fernet(key.encode())  # Codifica a chave de volta para bytes
    return f.encrypt(message.encode()).decode()

# Função para decriptografar a mensagem
def decrypt_message(encrypted_message, key):
    f = Fernet(key.encode())  # Codifica a chave de volta para bytes
    return f.decrypt(encrypted_message.encode()).decode()

from flask_login import current_user

@app.route('/chat/<int:turma_id>', methods=['GET', 'POST'])
@login_required
def chat(turma_id):
    turma = Turma.query.get_or_404(turma_id)

    # Garante que todas as turmas têm uma chave
    ensure_all_turmas_have_key()

    key = turma.key  

    mensagens = ChatMessage.query.filter_by(turma_id=turma.id).all()
    decrypted_messages = []
    for msg in mensagens:
        try:
            decrypted_msg = decrypt_message(msg.mensagem, key)
            rotulos = []
            if msg.user.is_gremio:
                rotulos.append('GRÊMIO')
            if msg.user.is_representante:
                rotulos.append('REPRESENTANTE')
            if msg.user.is_admin:
                rotulos.append('ADMINISTRADOR')
            decrypted_messages.append((msg.user.nome_completo, decrypted_msg, rotulos, msg.user.foto_perfil, msg.timestamp.strftime('%H:%M')))
        except InvalidToken:
            decrypted_messages.append((msg.user.nome_completo, "Mensagem inválida.", [], msg.user.foto_perfil, msg.timestamp.strftime('%H:%M')))

    return render_template('chat.html', turma=turma, mensagens=decrypted_messages)

@app.route('/manifest.json')
def manifest():
    return send_from_directory('static', 'manifest.json')

@socketio.on('send_message')
def handle_send_message_event(data):
    turma_id = data['turma_id']
    turma = Turma.query.get(turma_id)
    key = turma.key
    encrypted_message = encrypt_message(data['message'], key)

    new_message = ChatMessage(turma_id=turma_id, user_id=current_user.id, mensagem=encrypted_message)
    db.session.add(new_message)
    db.session.commit()

    rotulos = []
    if current_user.is_gremio:
        rotulos.append('GRÊMIO')
    if current_user.is_representante:
        rotulos.append('REPRESENTANTE')
    if current_user.is_admin:
        rotulos.append('ADMINISTRADOR')

    message_data = {
        'user_nome': current_user.nome_completo,
        'message': data['message'],
        'rotulos': rotulos,
        'foto_perfil': current_user.foto_perfil
    }

    emit('receive_message', message_data, room=str(turma_id))

@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)

@socketio.on('leave')
def on_leave(data):
    room = data['room']
    leave_room(room)


@app.route('/cardapio', methods=['GET', 'POST'])
@login_required
def cardapio():
    if request.method == 'POST':
        day = request.form['day']
        lunch = request.form['lunch']
        coffee = request.form['coffee']
        first_year_time = request.form['first_year_time']
        second_year_time = request.form['second_year_time']
        third_year_time = request.form['third_year_time']

        menu_item = Menu.query.filter_by(day=day).first()
        if menu_item:
            menu_item.lunch = lunch
            menu_item.coffee = coffee
            menu_item.first_year_time = first_year_time
            menu_item.second_year_time = second_year_time
            menu_item.third_year_time = third_year_time
        else:
            menu_item = Menu(
                day=day,
                lunch=lunch,
                coffee=coffee,
                first_year_time=first_year_time,
                second_year_time=second_year_time,
                third_year_time=third_year_time
            )
            db.session.add(menu_item)

        db.session.commit()
        flash('Cardápio atualizado com sucesso!', 'success')
        return redirect(url_for('cardapio'))

    menu_items = Menu.query.all()
    return render_template('cardapio.html', menu_items=menu_items, is_gremio=current_user.is_gremio)

@app.route('/contagem_faltas', methods=['GET', 'POST'])
@login_required
def contagem_faltas():
    if not current_user.is_representante:
        flash('Apenas representantes podem gerenciar as faltas.', 'danger')
        return redirect(url_for('index'))

    turmas = Turma.query.all()
    if request.method == 'POST':
        turma_id = request.form.get('turma_id')
        if turma_id:
            return redirect(url_for('marcar_faltas', turma_id=turma_id))
    return render_template('selecao_turma_faltas.html', turmas=turmas)

@app.route('/marcar_faltas/<int:turma_id>', methods=['GET', 'POST'])
@login_required
def marcar_faltas(turma_id):
    # Verifica se o usuário é um representante
    if not current_user.is_representante:
        flash('Apenas representantes podem gerenciar as faltas.', 'danger')
        return redirect(url_for('index'))

    # Obtém a turma que está sendo acessada
    turma = Turma.query.get_or_404(turma_id)

    # Verifica se a turma do representante logado é a mesma que a turma acessada
    if turma.id != current_user.turma_id:
        flash('Você não tem permissão para gerenciar faltas nesta turma.', 'danger')
        return redirect(url_for('contagem_faltas'))

    alunos = User.query.filter_by(turma_id=turma.id).all()
    mes_atual = datetime.now().month
    dias_do_mes = [datetime(datetime.now().year, mes_atual, dia) for dia in range(1, 32) if datetime(datetime.now().year, mes_atual, dia).month == mes_atual]

    # Dicionário para armazenar o status atual das faltas
    faltas = {}
    for aluno in alunos:
        faltas[aluno.id] = {}
        for dia in dias_do_mes:
            falta_existente = Falta.query.filter_by(user_id=aluno.id, data=dia, turma_id=turma.id).first()
            if falta_existente:
                if falta_existente.presente:
                    faltas[aluno.id][dia.day] = 'presente'
                elif falta_existente.falta_justificada:
                    faltas[aluno.id][dia.day] = 'falta_justificada'
                else:
                    faltas[aluno.id][dia.day] = 'falta'
            else:
                faltas[aluno.id][dia.day] = 'sem_aula'

    if request.method == 'POST':
        for aluno in alunos:
            for dia in dias_do_mes:
                status = request.form.get(f'presente_{aluno.id}_{dia.day}')
                falta_existente = Falta.query.filter_by(user_id=aluno.id, data=dia, turma_id=turma.id).first()

                if status == 'presente':
                    if falta_existente:
                        db.session.delete(falta_existente)
                    else:
                        nova_falta = Falta(user_id=aluno.id, data=dia, presente=True, turma_id=turma.id)
                        db.session.add(nova_falta)

                elif status == 'falta':
                    if falta_existente:
                        falta_existente.presente = False
                        falta_existente.falta_justificada = False
                    else:
                        nova_falta = Falta(user_id=aluno.id, data=dia, presente=False, turma_id=turma.id)
                        db.session.add(nova_falta)

                elif status == 'falta_justificada':
                    if falta_existente:
                        falta_existente.presente = False
                        falta_existente.falta_justificada = True
                    else:
                        nova_falta = Falta(user_id=aluno.id, data=dia, presente=False, falta_justificada=True, turma_id=turma.id)
                        db.session.add(nova_falta)

                elif status == 'sem_aula':
                    if falta_existente:
                        db.session.delete(falta_existente)

        db.session.commit()
        flash('Faltas atualizadas com sucesso!', 'success')
        return redirect(url_for('contagem_faltas'))

    return render_template('marcar_faltas.html', turma=turma, alunos=alunos, dias_do_mes=dias_do_mes, faltas=faltas)

@app.route('/favicon.ico')
def fiv():
    return send_from_directory('static', 'favicon.ico')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        nome_completo = request.form.get('nome_completo')
        turma_nome = request.form.get('turma')
        data_nascimento = request.form.get('data_nascimento')
        email = request.form.get('email')
        senha = request.form.get('senha')
        confirmar_senha = request.form.get('confirmar_senha')

        if not all([nome_completo, turma_nome, data_nascimento, email, senha, confirmar_senha]):
            flash('Por favor, preencha todos os campos.', 'error')
            return redirect(url_for('signup'))

        if senha != confirmar_senha:
            flash('As senhas não coincidem.', 'error')
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash('Email já cadastrado.', 'error')
            return redirect(url_for('signup'))

        turma = Turma.query.filter_by(nome=turma_nome).first()
        if not turma:
            flash('Turma não encontrada.', 'error')
            return redirect(url_for('signup'))

        try:
            data_nascimento = datetime.strptime(data_nascimento, '%Y-%m-%d').date()
        except ValueError:
            flash('Data de nascimento inválida.', 'error')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(senha)

        novo_usuario = User(
            nome_completo=nome_completo,
            turma=turma,
            data_nascimento=data_nascimento,
            email=email,
            senha_hash=hashed_password
        )

        try:
            db.session.add(novo_usuario)
            db.session.commit()
            flash('Cadastro realizado com sucesso!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            print(f"Erro ao cadastrar usuário: {e}")
            flash('Ocorreu um erro ao realizar o cadastro. Tente novamente.', 'error')
            return redirect(url_for('signup'))

    return render_template('signup.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
