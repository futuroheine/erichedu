from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from werkzeug.security import generate_password_hash
import requests
from datetime import datetime

app = Flask(__name__)
login_manager = LoginManager(app)
app.config['SECRET_KEY'] = 'futuroheine2024'

# Configuração da base de dados (usando Supabase com PostgreSQL)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres.siihlnhoryxbdhrkkmie:futuroheine2024@aws-0-sa-east-1.pooler.supabase.com:6543/postgres'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nome_completo = db.Column(db.String(150), nullable=False)
    data_nascimento = db.Column(db.Date, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha_hash = db.Column(db.String(128), nullable=False)
    turma_id = db.Column(db.Integer, db.ForeignKey('turma.id'), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Adicionado campo is_admin
    is_gremio = db.Column(db.Boolean, default=False)  # Para membros do grêmio estudantil
    is_representante = db.Column(db.Boolean, default=False)  # Para representantes de turma

    turma = db.relationship('Turma', backref='estudantes', lazy=True)

class Turma(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(10), nullable=False)

    alunos = db.relationship('User', backref='turma_associada', lazy=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('welcome.html')

# Função disponível apenas para administradores
@app.route('/admin_area')
@login_required
def admin_area():
    if not current_user.is_admin:
        flash('Acesso restrito a administradores.', 'danger')
        return redirect(url_for('index'))
    
    return render_template('admin_area.html')

# Exemplo de função para acessar as matérias da aula (somente admins)
@app.route('/upload_materia', methods=['POST'])
@login_required
def upload_materia():
    if not current_user.is_admin:
        flash('Apenas representantes e o grêmio podem enviar matérias.', 'danger')
        return redirect(url_for('index'))
    
    # Lógica para fazer upload de matérias
    # ...

    return "Matéria enviada com sucesso!"

# Função para quadro de almoço (disponível apenas para o grêmio estudantil)
@app.route('/quadro_almoco')
@login_required
def quadro_almoco():
    if not current_user.is_gremio:
        flash('Apenas o grêmio estudantil pode gerenciar o quadro de almoço.', 'danger')
        return redirect(url_for('index'))

    # Lógica para upload do quadro de almoço
    # ...

    return "Quadro de almoço atualizado com sucesso!"

# Função para contagem de faltas (apenas para representantes de turma)
@app.route('/contagem_faltas')
@login_required
def contagem_faltas():
    if not current_user.is_representante:
        flash('Apenas representantes podem gerenciar as faltas.', 'danger')
        return redirect(url_for('index'))

    # Lógica para fazer a contagem de faltas
    # ...

    return "Contagem de faltas atualizada com sucesso!"

# Rota para Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        nome_completo = request.form.get('nome_completo')
        turma_nome = request.form.get('turma')
        data_nascimento = request.form.get('data_nascimento')
        email = request.form.get('email')
        senha = request.form.get('senha')

        # Imprimir os dados para verificar
        print(f"Nome: {nome_completo}, Turma: {turma_nome}, Data de Nascimento: {data_nascimento}, Email: {email}, Senha: {senha}")

        if not nome_completo or not turma_nome or not data_nascimento or not email or not senha:
            flash('Por favor, preencha todos os campos.', 'error')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(email=email).first():
            flash('Email já cadastrado.', 'error')
            return redirect(url_for('signup'))

        turma = Turma.query.filter_by(nome=turma_nome).first()
        print(f"Turma encontrada: {turma}")  # Verifica se a turma foi encontrada

        if not turma:
            flash('Turma não encontrada.', 'error')
            return redirect(url_for('signup'))

        novo_usuario = User(
            nome_completo=nome_completo,
            turma_id=turma.id,
            data_nascimento=datetime.strptime(data_nascimento, '%Y-%m-%d'),
            email=email,
            senha_hash=generate_password_hash(senha)
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
        db.create_all()  # Cria todas as tabelas no banco de dados
    app.run(debug=True)
