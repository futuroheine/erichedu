from flask import Flask, render_template, redirect, url_for, flash, session, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from google.cloud import storage
import hashlib
import uuid
import firebase_admin
from firebase_admin import credentials
from cryptography.fernet import Fernet, InvalidToken
import random
from flask_socketio import SocketIO, emit, join_room, leave_room
import eventlet
from pytz import timezone  
from datetime import datetime, timedelta
from wtforms import StringField, TextAreaField, SelectField, BooleanField, SubmitField
from wtforms.validators import DataRequired



app = Flask(__name__)
login_manager = LoginManager(app)
app.config['SECRET_KEY'] = 'DeusSejaLouvado'
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
    avisos = db.relationship('Aviso', back_populates='turma')

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
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone('America/Sao_Paulo')))  # Campo de timestamp
    turma = db.relationship('Turma', back_populates='mensagens')
    user = db.relationship('User', back_populates='mensagens')

Turma.mensagens = db.relationship('ChatMessage', order_by=ChatMessage.timestamp, back_populates='turma')
User.mensagens = db.relationship('ChatMessage', order_by=ChatMessage.timestamp, back_populates='user')

class Materia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    turma_id = db.Column(db.Integer, db.ForeignKey('turma.id'), nullable=False)
    dia_da_semana = db.Column(db.String(20), nullable=False)
    professor = db.Column(db.String(100), nullable=False)
    imagem_url = db.Column(db.String(255), nullable=True)  # Campo para armazenar o link da imagem da matéria
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone('America/Sao_Paulo')))  # Campo de timestamp
    turma = db.relationship('Turma', back_populates='materias')

Turma.materias = db.relationship('Materia', back_populates='turma')

class QH(db.Model):
    __tablename__ = 'qh'
    id = db.Column(db.Integer, primary_key=True)
    materia = db.Column(db.String(100), nullable=False)  # Nome da matéria
    professor = db.Column(db.String(100), nullable=False)  # Nome do professor
    horario = db.Column(db.Time, nullable=False)  # Campo de horário
    turma_id = db.Column(db.Integer, db.ForeignKey('turma.id'), nullable=False)
    dia_da_semana = db.Column(db.String(10), nullable=False)

    def __repr__(self):
        return f'<QH {self.id}: {self.materia} - {self.professor} - {self.horario} - {self.dia_da_semana} - Turma ID {self.turma_id}>'
    
from flask_wtf import FlaskForm
from wtforms import StringField, TimeField, SelectField, SubmitField
from wtforms.validators import DataRequired, Optional

class QHForm(FlaskForm):
    materia = StringField('Matéria', validators=[DataRequired()])
    professor = StringField('Professor', validators=[DataRequired()])
    horario = TimeField('Horário', format='%H:%M', validators=[DataRequired()])
    dia_da_semana = SelectField('Dia da Semana', choices=[
        ('segunda', 'Segunda-feira'),
        ('terca', 'Terça-feira'),
        ('quarta', 'Quarta-feira'),
        ('quinta', 'Quinta-feira'),
        ('sexta', 'Sexta-feira'),
        ('sabado', 'Sábado'),
        ('domingo', 'Domingo')
    ], validators=[DataRequired()])  # Novo campo para o dia da semana
    turma_id = SelectField('Turma', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Adicionar QH')

class Aviso(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(255), nullable=False)
    mensagem = db.Column(db.Text, nullable=False)
    tipo_aviso = db.Column(db.String(50), nullable=False)  # gremio, representante, direção, administrador
    turma_id = db.Column(db.Integer, db.ForeignKey('turma.id'), nullable=True)  # Campo opcional para avisos específicos de turma
    serie = db.Column(db.String(20), nullable=True)  # Campo opcional para avisos específicos de série
    geral = db.Column(db.Boolean, default=False)  # Aviso geral para todos

    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone('America/Sao_Paulo')))

    turma = db.relationship('Turma', back_populates='avisos')

    def get_label(self):
        # Função para retornar a cor do rótulo baseado no tipo de aviso
        labels = {
            'gremio': 'var(--secondary-color)',  # Verde vibrante
            'representante': 'var(--accent-color)',  # Amarelo
            'direcao': 'var(--primary-color)',  # Azul escuro
            'administrador': 'var(--gray-dark)'  # Cinza escuro
        }
        return labels.get(self.tipo_aviso, 'var(--gray-light)')  # Retorna cinza claro por padrão

class AvisoForm(FlaskForm):
    titulo = StringField('Título', validators=[DataRequired()])
    mensagem = TextAreaField('Mensagem', validators=[DataRequired()])
    tipo_aviso = SelectField('Tipo de Aviso', choices=[
        ('gremio', 'Grêmio'),
        ('representante', 'Representante'),
        ('direcao', 'Direção'),
        ('administrador', 'Administrador')
    ], validators=[DataRequired()])
    turma_id = SelectField('Turma', coerce=int, choices=[], validators=[Optional()])  # Agora é opcional
    serie = SelectField('Série', choices=[
        ('1', '1º Ano'),
        ('2', '2º Ano'),
        ('3', '3º Ano')
    ], validators=[Optional()])  # Agora é opcional
    geral = BooleanField('Aviso Geral', default=False)
    submit = SubmitField('Enviar Aviso')

@app.route('/add_qh', methods=['GET', 'POST'])
def add_qh():
    form = QHForm()
    form.turma_id.choices = [(turma.id, turma.nome) for turma in Turma.query.all()]

    if form.validate_on_submit():
        nova_aula = QH(
            materia=form.materia.data,
            professor=form.professor.data,
            horario=form.horario.data,
            dia_da_semana=form.dia_da_semana.data,  # Novo campo
            turma_id=form.turma_id.data
        )
        db.session.add(nova_aula)
        db.session.commit()
        flash('Aula adicionada com sucesso!', 'success')
        return redirect(url_for('add_qh'))

    return render_template('add_qh.html', form=form, user=current_user)



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

@app.route('/materias', methods=['GET'])
@login_required
def materias():
    # Verifica a turma do usuário atual
    turma = current_user.turma

    # Se a turma não for encontrada ou o usuário não tiver uma turma associada
    if not turma:
        flash('Você não está associado a nenhuma turma.', 'danger')
        return redirect(url_for('index'))

    # Busca todas as matérias da turma do usuário, ordenadas da mais nova para a mais antiga
    materias = Materia.query.filter_by(turma_id=turma.id).order_by(Materia.id.desc()).all()

    # Renderiza a página com as matérias
    return render_template('materias.html', materias=materias)


@app.route('/upload_materia', methods=['GET', 'POST'])
@login_required
def upload_materia():
    # Verifica se o usuário é administrador, do grêmio ou representante
    if not current_user.is_admin and not current_user.is_gremio and not current_user.is_representante:
        flash('Apenas administradores, grêmio ou representantes podem enviar matérias.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Obtém os dados do formulário
        nome_materia = request.form.get('nome_materia')
        turma_nome = request.form.get('turma_nome')  # O nome da turma fornecido
        dia_da_semana = request.form.get('dia_da_semana')
        professor = request.form.get('professor')
        imagem_materia = request.files.get('imagem_materia')

        # Verifica se a turma existe no banco de dados
        turma = Turma.query.filter_by(nome=turma_nome).first()  # Busca a turma pelo nome

        if not turma:
            flash(f'Turma {turma_nome} não encontrada.', 'danger')
            return redirect(url_for('upload_materia'))

        turma_id = turma.id  # Obtém o ID da turma encontrada

        # Verifica se o arquivo de imagem está presente e válido
        if imagem_materia:
            imagem_url = save_profile_picture(imagem_materia)
        else:
            imagem_url = None

        # Cria uma nova matéria
        nova_materia = Materia(
            nome=nome_materia,
            turma_id=turma_id,  # Usa o turma_id encontrado
            dia_da_semana=dia_da_semana,
            professor=professor,
            imagem_url=imagem_url
        )

        # Adiciona e confirma a nova matéria no banco de dados
        db.session.add(nova_materia)
        db.session.commit()

        flash('Matéria enviada com sucesso!', 'success')
        return redirect(url_for('home'))

    # Renderiza o formulário caso seja uma requisição GET
    return render_template('enviar_materia.html')




@app.route('/home')
@login_required
def home():
    user = User.query.get(session['user_id'])
    
    # Obter a turma do usuário
    turma_id = user.turma_id
    
    # Criar um dicionário para mapear dias da semana
    dias_da_semana = {
        'monday': 'segunda',
        'tuesday': 'terça',
        'wednesday': 'quarta',
        'thursday': 'quinta',
        'friday': 'sexta',
        'saturday': 'sábado',
        'sunday': 'domingo'
    }
    
    # Determinar o dia da semana atual em inglês e converter para português
    dia_atual_ingles = datetime.now().strftime('%A').lower()
    dia_atual = dias_da_semana.get(dia_atual_ingles, dia_atual_ingles)

    horario_atual = datetime.now().time()

    # Buscar a próxima aula
    proxima_aula = QH.query.filter_by(turma_id=turma_id, dia_da_semana=dia_atual).filter(QH.horario > horario_atual).order_by(QH.horario).first()

    # Buscar avisos recentes da turma do usuário
    avisos = Aviso.query.filter_by(turma_id=turma_id).order_by(Aviso.timestamp.desc()).limit(5).all()

    return render_template('home.html', user=user, proxima_aula=proxima_aula, avisos=avisos)


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
    # Filtrando apenas as faltas que não são presentes e não são justificadas
    faltas = Falta.query.filter_by(user_id=current_user.id, presente=False, falta_justificada=False).all()
    total_faltas = len(faltas)
    return render_template('eu.html', user=user, faltas_count=total_faltas)


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

from pusher import Pusher

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

    # Envia um evento de atualização ao Pusher
    pusher_client.trigger(f'turma-{turma_id}', 'new-message', {
        'messages': decrypted_messages
    })

    return render_template('chat.html', turma=turma, mensagens=decrypted_messages)


# Configuração do Pusher
app_id = "1882919"
key = "4df4366db18a7f9ff11e"
secret = "c0ca49da33ad35aba25a"
cluster = "sa1"

pusher_client = Pusher(
    app_id=app_id,
    key=key,
    secret=secret,
    cluster=cluster,
    ssl=True
)

@app.route('/send_message', methods=['POST'])
def handle_send_message():
    data = request.json  # Use a estrutura JSON conforme o necessário
    turma_id = data['turma_id']
    mensagem = data['message']
    time = data['time']

    # Obtendo a turma para a chave de criptografia
    turma = Turma.query.get(turma_id)  # Certifique-se de que Turma está importado
    key = turma.key

    # Criptografando a mensagem
    encrypted_message = encrypt_message(mensagem, key)

    # Salvando a mensagem no banco de dados
    new_message = ChatMessage(turma_id=turma_id, user_id=current_user.id, mensagem=encrypted_message)
    db.session.add(new_message)
    db.session.commit()

    # Criando a estrutura de dados para enviar via Pusher
    rotulos = []
    if current_user.is_gremio:
        rotulos.append('GRÊMIO')
    if current_user.is_representante:
        rotulos.append('REPRESENTANTE')
    if current_user.is_admin:
        rotulos.append('ADMINISTRADOR')

    message_data = {
        'user_nome': current_user.nome_completo,
        'message': mensagem,  # Mensagem original para exibição
        'rotulos': rotulos,
        'time': time,
        'foto_perfil': current_user.foto_perfil  # Incluindo a foto de perfil se necessário
    }

    # Emitindo a mensagem para o canal Pusher
    pusher_client.trigger(f'turma-{turma_id}', 'new-message', message_data)

    return "Mensagem enviada com sucesso!"  # Retornando uma resposta simples

 
@app.route('/manifest.json')
def manifest():
    return send_from_directory('static', 'manifest.json')


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
    return render_template('cardapio.html', menu_items=menu_items, is_gremio=current_user.is_gremio, user=current_user)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    # Verifica se o usuário é administrador
    if not current_user.is_admin:
        flash('Acesso negado. Apenas administradores podem acessar esta página.', 'danger')
        return redirect(url_for('index'))

    # Instancia o formulário AvisoForm
    qh_form = QHForm()
    aviso_form = AvisoForm()
    menus = Menu.query.all()
    turmas = Turma.query.all()
    faltas = Falta.query.all()

    # Popula as opções de turma
    aviso_form.turma_id.choices = [(t.id, t.nome) for t in Turma.query.all()]  # Lista de opções de turma

    # Se o formulário for enviado e validado
    if aviso_form.validate_on_submit():
        # Lógica para adicionar um novo aviso
        novo_aviso = Aviso(
            titulo=aviso_form.titulo.data,
            mensagem=aviso_form.mensagem.data,
            tipo_aviso=aviso_form.tipo_aviso.data,
            geral=aviso_form.geral.data
        )

        # Se o aviso não for geral, verificar turma e série
        if not aviso_form.geral.data:
            novo_aviso.turma_id = aviso_form.turma_id.data if aviso_form.turma_id.data else None
            novo_aviso.serie = aviso_form.serie.data if aviso_form.serie.data else None

        db.session.add(novo_aviso)
        db.session.commit()
        flash('Aviso adicionado com sucesso!', 'success')
        return redirect(url_for('admin'))

    return render_template('admin.html', aviso_form=aviso_form, qh_form=qh_form, menus=menus, turmas=turmas, faltas=faltas)

@app.route('/delete_menu/<int:menu_id>', methods=['POST'])
@login_required
def delete_menu(menu_id):
    menu = Menu.query.get_or_404(menu_id)
    db.session.delete(menu)
    db.session.commit()
    flash('Cardápio excluído com sucesso!', 'success')
    return redirect(url_for('admin'))


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

@app.route('/test')
def test():
    return "rota teste"

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
