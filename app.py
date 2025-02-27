from flask import Flask, render_template, jsonify, redirect, url_for, flash, session, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from google.cloud import storage
import hashlib
import uuid
import logging
import svglib
import firebase_admin
from reportlab.graphics import renderPM
from firebase_admin import credentials
from cryptography.fernet import Fernet, InvalidToken
import random
from flask_socketio import SocketIO, emit, join_room, leave_room
import eventlet
from pytz import timezone  
from datetime import datetime, timedelta
import pytz, os
import mimetypes
from io import BytesIO

# Criar instância do SQLAlchemy SEM passar app ainda
db = SQLAlchemy()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'futuroheine2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres.siihlnhoryxbdhrkkmie:futuroheine2024@aws-0-sa-east-1.pooler.supabase.com:6543/postgres'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializar `db` APÓS configurar o app
db.init_app(app)

login_manager = LoginManager(app)
socketio = SocketIO(app)



cred = credentials.Certificate("serviceAccountKey.json")
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred, {
        'storageBucket': 'gs://app-erichedu.appspot.com'
    })

from pytz import timezone

def horario_atual_brasilia():
    fuso_brasilia = timezone('America/Sao_Paulo')
    return datetime.now(fuso_brasilia)

print(horario_atual_brasilia())

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
    matrix_access_token = db.Column(db.String(500), nullable=True)  # Ajuste o tamanho conforme necessário


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
    key = db.Column(db.String(255), nullable=True)  # Coluna existente

    alunos = db.relationship('User', back_populates='turma')
    faltas = db.relationship('Falta', back_populates='turma')

    # Relacionamento muitos para muitos com avisos
    avisos = db.relationship('Aviso', secondary='aviso_turma', back_populates='turmas')

    def __repr__(self):
        return f'Turma {self.nome}'
    

class Suporte(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    numero = db.Column(db.String(20), nullable=False)
    assunto = db.Column(db.String(200), nullable=False)
    mensagem = db.Column(db.Text, nullable=False)
    data_envio = db.Column(db.DateTime, default=horario_atual_brasilia)
    status = db.Column(db.String(20), default='pendente')
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    usuario = db.relationship('User', backref='suportes')

    def __repr__(self):
        return f'<Suporte {self.id} - {self.nome}>'


aviso_turma = db.Table('aviso_turma',
    db.Column('aviso_id', db.Integer, db.ForeignKey('aviso.id'), primary_key=True),
    db.Column('turma_id', db.Integer, db.ForeignKey('turma.id'), primary_key=True)
)


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

class Aviso(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(255), nullable=False)
    mensagem = db.Column(db.Text, nullable=False)
    tipo_aviso = db.Column(db.String(50), nullable=False)
    serie = db.Column(db.Integer, nullable=True)
    geral = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)

    # Relacionamento muitos para muitos com turmas
    turmas = db.relationship('Turma', secondary='aviso_turma', back_populates='avisos')

    def __repr__(self):
        return f'Aviso {self.titulo}'


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
from wtforms.validators import DataRequired

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


class Teacher(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nome_completo = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha_hash = db.Column(db.String(128), nullable=False)
    
    # O método get_id() inclui um prefixo para diferenciar dos alunos
    def get_id(self):
        return f"teacher-{self.id}"

# Configurações do Firebase Storage
storage_client = storage.Client.from_service_account_json("serviceAccountKey.json")
bucket_name = "app-erichedu.appspot.com"  # Nome do seu bucket do Firebase Storage

from flask import Flask, request, jsonify, session
from google.cloud import storage
from datetime import datetime
import logging
import io
import requests
from PIL import Image
import base64
from xml.etree import ElementTree as ET
import re

@app.route('/save-avatar', methods=['POST'])
def save_avatar():
    data = request.json
    img_url = data.get('imgURL')
    user_id = session.get('user_id')

    if not img_url or not user_id:
        logging.error('Erro: URL da imagem ou ID do usuário não fornecido')
        return jsonify({'error': 'URL da imagem ou ID do usuário não fornecido'}), 400

    logging.debug(f'Imagem URL: {img_url}')
    logging.debug(f'User ID: {user_id}')

    # Download SVG from avataaars.io
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(img_url, headers=headers)
        if response.status_code != 200:
            logging.error(f'Erro ao baixar a imagem, status code: {response.status_code}')
            return jsonify({'error': 'Erro ao baixar a imagem'}), 400
        
        # Convert SVG to data URL
        svg_content = response.content.decode('utf-8')
        
        # Check if the content is already a data URL
        if not svg_content.startswith('data:image/svg+xml;base64,'):
            # Convert to base64 data URL
            base64_svg = base64.b64encode(svg_content.encode('utf-8')).decode('utf-8')
            data_url = f'data:image/svg+xml;base64,{base64_svg}'
        else:
            data_url = svg_content

    except Exception as e:
        logging.error(f'Erro ao processar a imagem SVG: {e}')
        return jsonify({'error': 'Erro ao processar a imagem SVG'}), 400

    # Now we can save the data URL directly to Firebase
    try:
        storage_client = storage.Client.from_service_account_json("serviceAccountKey.json")
        bucket = storage_client.bucket("app-erichedu.appspot.com")
        
        timestamp = horario_atual_brasilia().strftime('%Y%m%d_%H%M%S')
        # Save as SVG instead of PNG
        blob_name = f'avatars/avatar-{user_id}_{timestamp}.svg'
        
        # Remove the data URL prefix if present and decode
        if data_url.startswith('data:image/svg+xml;base64,'):
            svg_data = base64.b64decode(data_url.split(',')[1])
        else:
            svg_data = svg_content.encode('utf-8')
        
        blob = bucket.blob(blob_name)
        blob.upload_from_string(svg_data, content_type='image/svg+xml')
        blob.make_public()
        download_url = blob.public_url
        
        logging.debug(f'Imagem enviada para o Firebase: {download_url}')
    except Exception as e:
        logging.error(f'Erro no upload para o Firebase: {e}')
        return jsonify({'error': 'Erro no upload para o Firebase'}), 500

    # Update database
    try:
        user = db.session.get(User, user_id)
        if not user:
            logging.error('Usuário não encontrado')
            return jsonify({'error': 'Usuário não encontrado'}), 404

        user.foto_perfil = download_url
        db.session.commit()
        logging.debug(f'Foto de perfil do usuário {user_id} atualizada para {download_url}')
        return jsonify({'message': 'Foto de perfil atualizada com sucesso', 'foto_perfil': download_url}), 200
    except Exception as e:
        logging.error(f'Erro ao atualizar o banco de dados: {e}')
        return jsonify({'error': 'Erro ao atualizar o banco de dados'}), 500

@app.route('/add_qh', methods=['GET', 'POST'])
def add_qh():
    form = QHForm()
    form.turma_id.choices = [(turma.id, turma.nome) for turma in Turma.query.all()]

    # Obter a turma do usuári
    user = db.session.get(User, session.get('user_id'))
    turma_id = user.turma_id
    cor_primaria = determinar_cor_primaria(turma_id)
    turma = current_user.turma

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

    return render_template('add_qh.html', form=form, primary_collor=cor_primaria, user=current_user)



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


fuso_brasilia = pytz.timezone('America/Sao_Paulo')

# Obtenha o horário atual no fuso de Brasília
horario_atual = datetime.now(fuso_brasilia)

def determinar_cor_primaria(turma_id):
    # Mapear os intervalos de turmas para as cores
    if 1 <= turma_id <= 4:
        return "#083888"  # Azul escuro
    elif 6 <= turma_id <= 9:
        return "#FFD21F"  # Amarelo
    elif 11 <= turma_id <= 14:
        return "#d40000"  # Vermelho (escolhido como um vermelho forte e marcante)
    elif turma_id in [5, 10, 15]:
        return "#78ac54"  # Verde vibrante
    else:
        return "#083888"  # Cinza padrão para turmas fora do intervalo



@app.route('/')
def index():
    return render_template('welcome.html')

@login_manager.user_loader
def load_user(user_id):
    # Verifica se o ID possui o prefixo "teacher-"
    if user_id.startswith("teacher-"):
        teacher_id = int(user_id.split("-")[1])
        return Teacher.query.get(teacher_id)
    else:
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
    user = db.session.get(User, session.get('user_id'))
    
    # Obter a turma do usuário
    turma_id = user.turma_id
    cor_primaria = determinar_cor_primaria(turma_id)
    turma = current_user.turma

    # Se a turma não for encontrada ou o usuário não tiver uma turma associada
    if not turma:
        flash('Você não está associado a nenhuma turma.', 'danger')
        return redirect(url_for('index'))

    # Busca todas as matérias da turma do usuário, ordenadas da mais nova para a mais antiga
    materias = Materia.query.filter_by(turma_id=turma.id).order_by(Materia.id.desc()).all()

    # Renderiza a página com as matérias
    return render_template('materias.html', materias=materias, primary_collor=cor_primaria)


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


@app.context_processor
def inject_user():
    user_id = session.get('user_id')
    if user_id:
        user = db.session.get(User, user_id)  # Método atualizado
        return {'user': user}  # Variável user disponível em todos os templates
    return {'user': None}  # Caso o usuário não esteja logado

@app.route('/home')
@login_required
def home():
    user = db.session.get(User, session.get('user_id'))
    
    # Obter a turma do usuário
    turma_id = user.turma_id
    cor_primaria = determinar_cor_primaria(turma_id)
    
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
    dia_atual = dias_da_semana.get(dia_atual_ingles, dia_atual_ingles)  # Pega o dia em pt-BR

    # Defina o fuso horário de Brasília
    fuso_brasilia = pytz.timezone('America/Sao_Paulo')

    # Obtenha o horário atual no fuso de Brasília
    horario_atual = datetime.now(fuso_brasilia).time()

    # Buscar a próxima aula
    proxima_aula = QH.query.filter_by(turma_id=turma_id, dia_da_semana=dia_atual).filter(QH.horario > horario_atual).order_by(QH.horario).first()

    # Buscar apenas os avisos relacionados à turma do usuário
    avisos = Aviso.query.join(aviso_turma).filter(aviso_turma.c.turma_id == turma_id).order_by(Aviso.timestamp.desc()).all()
    
    return render_template('home.html', user=user, proxima_aula=proxima_aula, avisos=avisos, primary_collor=cor_primaria, hour=horario_atual)


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


@app.errorhandler(Exception)
def handle_exception(e):
    user = User.query.get(session['user_id'])
    turma_id = user.turma_id
    cor_primaria = determinar_cor_primaria(turma_id)
    # Log detalhado do erro (opcional, útil para depuração)
    app.logger.error(f"Erro: {e}")

    # Retornar página de erro amigável
    return render_template('error.html', primary_collor=cor_primaria, error_message=str(e)), 500

from datetime import datetime
from sqlalchemy.sql import extract


from collections import defaultdict

@app.route('/eu')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    turma_id = user.turma_id
    cor_primaria = determinar_cor_primaria(turma_id)

    # Obter todas as faltas do usuário
    faltas = Falta.query.filter_by(user_id=current_user.id, presente=False, falta_justificada=False).all()

    # Contador total de faltas
    total_faltas = len(faltas)

    # Data atual
    data_atual = datetime.now()

    # Contador de faltas apenas do mês atual
    faltas_mes = Falta.query.filter(
        Falta.user_id == current_user.id,
        Falta.presente == False,
        Falta.falta_justificada == False,
        extract('month', Falta.data) == data_atual.month,
        extract('year', Falta.data) == data_atual.year
    ).all()

    faltas_mes_count = len(faltas_mes)

    # Faltas por mês no ano atual
    faltas_por_mes = defaultdict(int)
    for falta in faltas:
        if falta.data.year == data_atual.year:
            faltas_por_mes[falta.data.month] += 1

    # Organizar os dados para o gráfico
    meses = list(range(1, 13))  # Meses de 1 a 12
    faltas_mensais = [faltas_por_mes.get(mes, 0) for mes in meses]

    return render_template(
        'eu.html',
        user=user,
        faltas_total=total_faltas,
        faltas_count=faltas_mes_count,
        primary_collor=cor_primaria,
        faltas_mensais=faltas_mensais,
        meses=meses
    )



# Função de upload de imagem
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'jpg', 'jpeg', 'png'}

def save_profile_picture(picture):
    if picture and allowed_file(picture.filename):
        ext = picture.filename.rsplit('.', 1)[1].lower()
        new_filename = f"{uuid.uuid4().hex}.{ext}"
        
        # Configuração do bucket
        client = storage.Client.from_service_account_json("serviceAccountKey.json")
        bucket = client.bucket("app-erichedu.appspot.com")
        
        blob = bucket.blob(new_filename)
        
        # Upload do arquivo
        blob.upload_from_file(picture, content_type="image/png")  # Ajuste o content_type se necessário
        blob.make_public()
        
        print(f"Upload bem-sucedido: {blob.public_url}")
        return blob.public_url
    else:
        print("Arquivo inválido ou tipo não suportado.")
        return None


# Rota para edição de perfil
@app.route('/editar_perfil', methods=['GET', 'POST'])
@login_required
def editar_perfil():

    user = User.query.get(session['user_id'])
    turma_id = user.turma_id
    cor_primaria = determinar_cor_primaria(turma_id)

    
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

    return render_template('editar_perfil.html', user=current_user, primary_collor=cor_primaria)

@app.route('/admin/suporte', methods=['GET'])
@login_required
def admin_suporte():
    user = User.query.get(session['user_id'])
    turma_id = user.turma_id
    cor_primaria = determinar_cor_primaria(turma_id)

    if not current_user.is_admin:
        flash('Acesso restrito a administradores.', 'danger')
        return redirect(url_for('home'))

    mensagens = Suporte.query.all()  # Pega todas as mensagens de suporte
    return render_template('admin_suporte.html', mensagens=mensagens, primary_collor=cor_primaria)

from flask import Flask, send_file
import csv

@app.route('/exportar', methods=['POST'])
def exportar():
    mensagens = Suporte.query.all()  # Pegue as mensagens do banco de dados
    with open('relatorio_mensagens.csv', 'w', newline='') as csvfile:
        fieldnames = ['Nome', 'Assunto', 'Mensagem', 'Contato', 'Data']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for mensagem in mensagens:
            writer.writerow({
                'Nome': mensagem.nome,
                'Assunto': mensagem.assunto,
                'Mensagem': mensagem.mensagem,
                'Contato': mensagem.numero,
                'Data': mensagem.data_envio.strftime('%d/%m/%Y %H:%M')
            })
    return send_file('relatorio_mensagens.csv', as_attachment=True)

@app.route('/filtrar', methods=['POST'])
def filtrar():
    status = request.form.get('status')
    mensagens = Suporte.query.filter_by(status=status).all()
    return render_template('admin_suport.html', mensagens=mensagens)

@app.route('/excluir_mensagem/<int:id>', methods=['POST'])
def excluir_mensagem(id):
    mensagem = Suporte.query.get(id)
    db.session.delete(mensagem)
    db.session.commit()
    return redirect(url_for('admin_suporte'))

@app.route('/mensagem/<int:id>', methods=['GET'])
@login_required
def ver_mensagem(id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores.', 'danger')
        return redirect(url_for('home'))

    # Busca a mensagem específica
    mensagem = Suporte.query.get_or_404(id)
    
    # Determina a cor primária da turma do usuário atual
    user = User.query.get(session['user_id'])
    cor_primaria = determinar_cor_primaria(user.turma_id)

    # Atualiza o status para 'em_andamento' quando a mensagem é visualizada
    if mensagem.status == 'pendente':
        mensagem.status = 'em_andamento'
        db.session.commit()

    return render_template('detalhe_mensagem.html', 
                           mensagem=mensagem, 
                           primary_collor=cor_primaria)

@app.route('/resolver_mensagem/<int:id>', methods=['POST'])
@login_required
def resolver_mensagem(id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores.', 'danger')
        return redirect(url_for('home'))

    mensagem = Suporte.query.get_or_404(id)
    mensagem.status = 'resolvido'
    db.session.commit()
    
    flash('Mensagem marcada como resolvida.', 'success')
    return redirect(url_for('admin_suporte'))

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
    user = User.query.get(session['user_id'])

    cor_primaria = determinar_cor_primaria(turma_id)

    # Garante que todas as turmas têm uma chave
    ensure_all_turmas_have_key()

    key = turma.key  

    mensagens = ChatMessage.query.filter_by(turma_id=turma.id).order_by(ChatMessage.timestamp).all()
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

    return render_template('chat.html', turma=turma, mensagens=decrypted_messages, user=user, primary_collor=cor_primaria)
import pusher

pusher_client = pusher.Pusher(
    app_id = "1882919",
    key = "4df4366db18a7f9ff11e",
    secret = "c0ca49da33ad35aba25a",
    cluster = "sa1",
    ssl=True
)

@app.route('/suporte', methods=['GET', 'POST'])
@login_required
def suporte():
    if request.method == 'POST':
        nome = request.form.get('nome')
        numero = request.form.get('numero')
        assunto = request.form.get('assunto')
        mensagem = request.form.get('mensagem')
        
        # Criar um novo registro na tabela de Suporte
        nova_mensagem = Suporte(nome=nome, numero=numero, assunto=assunto, mensagem=mensagem, usuario_id=current_user.id)
        
        # Salvar a mensagem no banco de dados
        db.session.add(nova_mensagem)
        db.session.commit()

        flash('Sua mensagem foi enviada com sucesso! Em breve entraremos em contato.', 'success')
        return redirect(url_for('suporte'))
    
    return render_template('suporte.html', 
                           user=current_user,
                           primary_collor=determinar_cor_primaria(current_user.turma_id))

@app.route('/send-message', methods=['POST'])
def send_message():
    data = request.get_json()
    turma_id = data['turma_id']
    message = data['message']

    # Encripta a mensagem (opcional)
    turma = Turma.query.get(turma_id)
    key = turma.key
    encrypted_message = encrypt_message(message, key)

    # Salva no banco de dados
    new_message = ChatMessage(
        turma_id=turma_id, user_id=current_user.id, mensagem=encrypted_message
    )
    db.session.add(new_message)
    db.session.commit()

    # Envia o evento para o Pusher
    pusher_client.trigger(f'chat-turma-{turma_id}', 'new-message', {
        'user_nome': current_user.nome_completo,
        'message': message,
    })

    return jsonify({'status': 'success'})

@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    emit('user_joined', {'user_nome': current_user.nome_completo}, room=room)

@socketio.on('leave')
def on_leave(data):
    room = data['room']
    leave_room(room)
    emit('user_left', {'user_nome': current_user.nome_completo}, room=room)

@app.route('/manifest.json')
def manifest():
    return send_from_directory('static', 'manifest.json')

@app.route('/projetos')
@login_required
def projetos():
    
    user = db.session.get(User, session.get('user_id'))
    # Obter a turma do usuário
    turma_id = user.turma_id

    cor_primaria = determinar_cor_primaria(turma_id)
    """
    Rota para a página de Projetos Socioambientais
    Requer login do usuário
    """
    # Você pode adicionar lógica adicional aqui se necessário, 
    # como buscar detalhes específicos dos projetos de um banco de dados
    
    # Renderiza o template de projetos
    return render_template('projetos.html', user=current_user, primary_collor=cor_primaria)

@app.route('/add_aviso', methods=['POST'])
def add_aviso():
    titulo = request.form.get('titulo')
    mensagem = request.form.get('mensagem')
    tipo_aviso = request.form.get('tipo_aviso')  # Pode ser 'geral', 'turma' ou 'serie'
    turmas_ids = request.form.getlist('turmas_ids')  # Lista de IDs das turmas selecionadas
    serie = request.form.get('serie')  # Série selecionada (1, 2 ou 3)
    geral = request.form.get('geral') == 'on'  # Checkbox para aviso geral

    # Mapeamento de séries para IDs de turmas
    series_para_turmas = {
        '1': [1, 2, 3, 4, 5],   # 1ª série
        '2': [6, 7, 8, 9, 10],  # 2ª série
        '3': [11, 12, 13, 14, 15]  # 3ª série
    }

    # Criar o novo aviso
    aviso = Aviso(
        titulo=titulo,
        mensagem=mensagem,
        tipo_aviso=tipo_aviso,
        serie=serie if tipo_aviso == 'serie' else None,  # Apenas para avisos por série
        geral=geral,
        timestamp=horario_atual_brasilia()
    )

    try:
        db.session.add(aviso)  # Adicionar o aviso à sessão
        db.session.flush()  # Forçar a criação do aviso para obter o ID

        if geral:
            # Associar o aviso a todas as turmas
            todas_turmas = Turma.query.all()
            for turma in todas_turmas:
                aviso.turmas.append(turma)

        elif tipo_aviso == 'turma' and turmas_ids:
            # Garantir que `turmas_ids` é uma lista de inteiros
            turmas_ids = [int(turma_id) for turma_id in turmas_ids]
            turmas = Turma.query.filter(Turma.id.in_(turmas_ids)).all()
            for turma in turmas:
                aviso.turmas.append(turma)

        elif tipo_aviso == 'serie' and serie in series_para_turmas:
            # Selecionar os IDs das turmas correspondentes à série
            serie_turmas_ids = series_para_turmas[serie]
            turmas = Turma.query.filter(Turma.id.in_(serie_turmas_ids)).all()
            for turma in turmas:
                aviso.turmas.append(turma)

        db.session.commit()
        return "Aviso adicionado com sucesso!"
    except Exception as e:
        db.session.rollback()
        return f"Erro ao adicionar aviso: {str(e)}", 400

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
    
    user = User.query.get(session['user_id'])
    # Obter a turma do usuário
    turma_id = user.turma_id

    cor_primaria = determinar_cor_primaria(turma_id)
    
    
    menu_items = Menu.query.all()
    return render_template('cardapio.html', menu_items=menu_items, primary_collor=cor_primaria, is_gremio=current_user.is_gremio, user=current_user)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    # Verifica se o usuário é administrador
    if not current_user.is_admin:
        flash('Acesso negado. Apenas administradores podem acessar esta página.', 'danger')
        return redirect(url_for('index'))

    # Instancia o formulário QHForm
    form = QHForm()

    # Se o formulário for enviado e validado
    if form.validate_on_submit():
        # Lógica para adicionar um novo QH baseado no formulário
        novo_qh = QH(
            materia=form.materia.data,
            professor=form.professor.data,
            horario=form.horario.data,
            turma_id=form.turma_id.data,
            dia_da_semana=form.dia_da_semana.data
        )
        db.session.add(novo_qh)
        db.session.commit()
        flash('QH adicionado com sucesso!', 'success')
        return redirect(url_for('admin'))

    # Busca os dados necessários para exibir na página
    menus = Menu.query.all()
    turmas = Turma.query.all()
    faltas = Falta.query.all()

    # Renderiza o template e passa o formulário
    return render_template('admin.html', form=form, menus=menus, turmas=turmas, faltas=faltas)

@app.route('/delete_menu/<int:menu_id>', methods=['POST'])
@login_required
def delete_menu(menu_id):
    menu = Menu.query.get_or_404(menu_id)
    db.session.delete(menu)
    db.session.commit()
    flash('Cardápio excluído com sucesso!', 'success')
    return redirect(url_for('admin'))


import calendar

@app.route('/marcar_faltas/<int:turma_id>', methods=['GET', 'POST'])
@login_required
def marcar_faltas(turma_id):
    user = User.query.get(session['user_id'])
    cor_primaria = determinar_cor_primaria(user.turma_id)

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

    # Corrige a criação dos dias do mês utilizando calendar.monthrange
    ano_atual = datetime.now().year
    mes_atual = datetime.now().month
    ultimo_dia = calendar.monthrange(ano_atual, mes_atual)[1]
    dias_do_mes = [datetime(ano_atual, mes_atual, dia) for dia in range(1, ultimo_dia + 1)]

    # Nomes dos meses em português
    meses_pt = [
        "Janeiro 2025", "Fevereiro 2025", "Março 2025", "Abril 2025", "Maio 2025", "Junho 2025",
        "Julho 2025", "Agosto 2025", "Setembro 2025", "Outubro 2025", "Novembro 2025", "Dezembro 2025"
    ]
    mes_nome = meses_pt[mes_atual - 1]

    # Dias da semana em português
    dias_semana_pt = [
        "Segunda-Feira", "Terça-Feira", "Quarta-Feira", "Quinta-Feira",
        "Sexta-Feira", "Sábado", "Domingo"
    ]

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
                        falta_existente.presente = True
                        falta_existente.falta_justificada = False
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
        return redirect(url_for('home'))

    return render_template(
        'marcar_faltas.html',
        turma=turma,
        primary_collor=cor_primaria,
        alunos=alunos,
        dias_do_mes=dias_do_mes,
        faltas=faltas,
        mes_nome=mes_nome,
        dias_semana_pt=dias_semana_pt
    )

@app.route('/criadores')
def criadores():
    
    user = User.query.get(session['user_id'])

    # Verifica se o usuário está logado
    if current_user.is_authenticated:
        turma = current_user.turma
        turma_id = turma.id if turma else None  # Verifica se turma existe
    else:
        turma = None
        turma_id = None

    if turma is None:
        primary_color = "#004a87"
    else:
        primary_color = determinar_cor_primaria(turma_id)

    print(primary_color)

    # Renderiza a página, passando os valores
    return render_template('criadores.html', primary_collor=primary_color, user=user, turma=turma, turma_id=turma_id)


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


from professor import prof_bp
app.register_blueprint(prof_bp)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)