from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from datetime import datetime


app = Flask(__name__)
login_manager = LoginManager(app)
app.config['SECRET_KEY'] = 'futuroheine2024'

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

    turma = db.relationship('Turma', back_populates='alunos')

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

    alunos = db.relationship('User', back_populates='turma')



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
        senha = request.form['senha']  # Usando "senha" em vez de "password"
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.senha_hash, senha):  # Verifica a senha hash
            login_user(user)  # Usando o Flask-Login para autenticar o usuário
            session['user_id'] = user.id
            flash('Login bem-sucedido!', 'success')
            return redirect(url_for('home'))  # Redirecionar para a página inicial
        else:
            flash('Email ou senha inválidos.', 'danger')
    
    return render_template('login.html')


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

@app.route('/home')
def home():
    if not session.get('user_id'):
        return redirect(url_for('login'))  # Redirecionar para a página de login se não estiver autenticado
    user = User.query.get(session['user_id'])  # Obtém os dados do usuário
    return render_template('home.html', user=user)  # Passa o objeto do usuário para o template

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logout bem-sucedido!', 'success')
    return redirect(url_for('login'))


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

@app.route('/eu')
@login_required
def profile():
    user = User.query.get(session['user_id'])  # Obtém os dados do usuário
    return render_template('eu.html', user=user)  # Exibir informações do usuário

@app.route('/chat')
@login_required
def chat():
    # Aqui você pode implementar a lógica do chat
    return render_template('chat.html')  # Página do chat

@app.route('/cardapio', methods=['GET', 'POST'])
@login_required
def cardapio():
    if request.method == 'POST':
        # Obter os dados do formulário
        day = request.form['day']
        lunch = request.form['lunch']
        coffee = request.form['coffee']
        first_year_time = request.form['first_year_time']
        second_year_time = request.form['second_year_time']
        third_year_time = request.form['third_year_time']

        # Adicionar ou atualizar o cardápio no banco de dados
        menu_item = Menu.query.filter_by(day=day).first()
        if menu_item:
            # Atualizar o item existente
            menu_item.lunch = lunch
            menu_item.coffee = coffee
            menu_item.first_year_time = first_year_time
            menu_item.second_year_time = second_year_time
            menu_item.third_year_time = third_year_time
        else:
            # Criar um novo item
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

    # Buscar os itens do cardápio para exibição
    menu_items = Menu.query.all()
    return render_template('cardapio.html', menu_items=menu_items, is_gremio=current_user.is_gremio)


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


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        nome_completo = request.form.get('nome_completo')
        turma_nome = request.form.get('turma')
        data_nascimento = request.form.get('data_nascimento')
        email = request.form.get('email')
        senha = request.form.get('senha')
        confirmar_senha = request.form.get('confirmar_senha')

        # Imprimir os dados para verificar
        print(f"Nome: {nome_completo}, Turma: {turma_nome}, Data de Nascimento: {data_nascimento}, Email: {email}, Senha: {senha}")

        # Verifica se todos os campos estão preenchidos
        if not all([nome_completo, turma_nome, data_nascimento, email, senha, confirmar_senha]):
            flash('Por favor, preencha todos os campos.', 'error')
            return redirect(url_for('signup'))

        if senha != confirmar_senha:
            flash('As senhas não coincidem.', 'error')
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash('Email já cadastrado.', 'error')
            return redirect(url_for('signup'))

        # Obter a instância da turma
        turma = Turma.query.filter_by(nome=turma_nome).first()
        if not turma:
            flash('Turma não encontrada.', 'error')
            return redirect(url_for('signup'))

        # Converter data_nascimento para objeto date
        try:
            data_nascimento = datetime.strptime(data_nascimento, '%Y-%m-%d').date()
        except ValueError:
            flash('Data de nascimento inválida.', 'error')
            return redirect(url_for('signup'))

        # Gerar hash da senha
        hashed_password = generate_password_hash(senha)

        # Criar novo usuário
        novo_usuario = User(
            nome_completo=nome_completo,
            turma=turma,  # Atribuir a instância de Turma
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
        db.create_all()  # Cria todas as tabelas no banco de dados
    app.run(host='0.0.0.0', port=5000)