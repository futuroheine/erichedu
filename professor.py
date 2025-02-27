from flask.views import MethodView
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from pytz import timezone
import calendar
from sqlalchemy import func
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

prof_bp = Blueprint('prof', __name__, url_prefix='/prof')

class TeacherRegister(MethodView):
    def post(self):
        with current_app.app_context():
            from app import db, Teacher  # Import atrasado para evitar circularidade

            nome = request.form.get('nome_completo')
            email = request.form.get('email')
            senha = request.form.get('senha')
            confirmar_senha = request.form.get('confirmar_senha')

            if not all([nome, email, senha, confirmar_senha]):
                flash('Preencha todos os campos.', 'danger')
                return redirect(url_for('prof.register'))
            if senha != confirmar_senha:
                flash('As senhas não conferem.', 'danger')
                return redirect(url_for('prof.register'))
            if Teacher.query.filter_by(email=email).first():
                flash('Email já cadastrado.', 'danger')
                return redirect(url_for('prof.register'))

            hashed_password = generate_password_hash(senha)

            novo_teacher = Teacher(
                nome_completo=nome,
                email=email,
                senha_hash=hashed_password
            )
            db.session.add(novo_teacher)
            db.session.commit()

            flash('Cadastro realizado com sucesso! Faça login para continuar.', 'success')
            return redirect(url_for('prof.login'))

# Classe para login de professores
class TeacherLogin(MethodView):
    def get(self):
        from app import Teacher  # Import local
        if current_user.is_authenticated and isinstance(current_user, Teacher):
            return redirect(url_for('prof.home'))
        return render_template('professor/login.html')

    def post(self):
        from app import Teacher  # Import local
        email = request.form.get('email')
        senha = request.form.get('senha')
        teacher = Teacher.query.filter_by(email=email).first()
        if teacher and check_password_hash(teacher.senha_hash, senha):
            login_user(teacher)
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('prof.home'))
        else:
            flash('Email ou senha incorretos.', 'danger')
            return redirect(url_for('prof.login'))

# Registro das rotas de autenticação no blueprint
prof_bp.add_url_rule('/register', view_func=TeacherRegister.as_view('register'), methods=['GET', 'POST'])
prof_bp.add_url_rule('/login', view_func=TeacherLogin.as_view('login'), methods=['GET', 'POST'])

# Rota protegida para professores
@prof_bp.route('/')
def home():
    from app import Turma, Materia, Falta, db  # Import local
    turmas = Turma.query.all()  # Ajuste conforme necessário para filtrar as turmas do professor
    materias_por_turma = db.session.query(
        Turma.id, Turma.nome, func.count(Materia.id)
    ).outerjoin(Materia).group_by(Turma.id).all()
    hoje = datetime.now(timezone('America/Sao_Paulo')).date()
    inicio_mes = hoje.replace(day=1)
    faltas_por_turma = db.session.query(
        Turma.id, Turma.nome, 
        func.count(Falta.id).filter(Falta.presente == False, Falta.falta_justificada == False).label('faltas'),
        func.count(Falta.id).filter(Falta.presente == False, Falta.falta_justificada == True).label('justificadas')
    ).outerjoin(Falta).filter(Falta.data >= inicio_mes).group_by(Turma.id).all()
    
    return render_template('professor/home.html', 
                           turmas=turmas, 
                           materias_por_turma=materias_por_turma,
                           faltas_por_turma=faltas_por_turma)
