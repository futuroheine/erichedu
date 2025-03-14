from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import uuid
from pytz import timezone

# Importando modelos da aplicação principal
from app import db, Teacher, Turma, Materia, QH, Falta, User, ChatMessage, Aviso, aviso_turma

# Inicializando o Blueprint
prof_bp = Blueprint('prof', __name__, url_prefix='/professor')

# Função para obter o horário atual no fuso de Brasília
def horario_atual_brasilia():
    fuso_brasilia = timezone('America/Sao_Paulo')
    return datetime.now(fuso_brasilia)

# Função para determinar a cor primária baseada no tipo de usuário professor
def determinar_cor_professor():
    return "#083888"  # Azul escuro para professores

@prof_bp.errorhandler(Exception)
def handle_exception(e):
    user = Teacher.query.get(session['professor_id'])
    
    cor_primaria = determinar_cor_professor
    # Log detalhado do erro (opcional, útil para depuração)
    #app.logger.error(f"Erro: {e}")

    # Retornar página de erro amigável
    return render_template('error.html', primary_collor=cor_primaria, error_message=str(e)), 500


# Rotas do Professor
@prof_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']
        
        # Verificar se o professor existe
        professor = Teacher.query.filter_by(email=email).first()
        
        if professor and check_password_hash(professor.senha_hash, senha):
            login_user(professor)
            session['professor_id'] = professor.id
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('prof.dashboard'))
        else:
            flash('Email ou senha inválidos.', 'danger')
    
    return render_template('professor/login.html')

@prof_bp.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome_completo = request.form['nome_completo']
        email = request.form['email']
        senha = request.form['senha']
        confirmar_senha = request.form['confirmar_senha']
        
        # Validações básicas
        if not all([nome_completo, email, senha, confirmar_senha]):
            flash('Por favor, preencha todos os campos.', 'danger')
            return redirect(url_for('prof.cadastro'))
        
        if senha != confirmar_senha:
            flash('As senhas não coincidem.', 'danger')
            return redirect(url_for('prof.cadastro'))
        
        # Verificar se o email já está em uso
        if Teacher.query.filter_by(email=email).first():
            flash('Este email já está cadastrado.', 'danger')
            return redirect(url_for('prof.cadastro'))
        
        # Criar novo professor
        hashed_password = generate_password_hash(senha)
        novo_professor = Teacher(
            nome_completo=nome_completo,
            email=email,
            senha_hash=hashed_password
        )
        
        try:
            db.session.add(novo_professor)
            db.session.commit()
            flash('Cadastro realizado com sucesso! Faça login para continuar.', 'success')
            return redirect(url_for('prof.login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao cadastrar: {str(e)}', 'danger')
            return redirect(url_for('prof.cadastro'))
    
    return render_template('professor/cadastro.html')

@prof_bp.route('/dashboard')
@login_required
def dashboard():
    # Verificar se o usuário é um professor
    if not session.get('professor_id'):
        flash('Acesso negado. Esta área é restrita para professores.', 'danger')
        return redirect(url_for('login'))
    
    # Obter o professor atual
    professor = Teacher.query.get(session['professor_id'])
    
    # Obter todas as aulas que o professor leciona
    aulas = QH.query.filter_by(professor=professor.nome_completo).all()
    
    # Obter turmas de todas as aulas
    turmas_ids = set(aula.turma_id for aula in aulas)
    turmas = Turma.query.filter(Turma.id.in_(turmas_ids)).all()

    # Obter as próximas aulas do professor
    hoje = datetime.now().strftime('%A').lower()
    dia_atual = {
        'monday': 'segunda',
        'tuesday': 'terca',
        'wednesday': 'quarta',
        'thursday': 'quinta',
        'friday': 'sexta',
        'saturday': 'sabado',
        'sunday': 'domingo'
    }.get(hoje)
    
    horario_atual = datetime.now(timezone('America/Sao_Paulo')).time()
    proximas_aulas = QH.query.filter_by(
        professor=professor.nome_completo,
        dia_da_semana=dia_atual
    ).filter(QH.horario > horario_atual).order_by(QH.horario).all()
    
    return render_template(
        'professor/dashboard.html',
        professor=professor,
        turmas=turmas,
        proximas_aulas=proximas_aulas,
        primary_collor=determinar_cor_professor()
    )




@prof_bp.route('/logout')
@login_required
def logout():
    session.pop('professor_id', None)
    logout_user()
    flash('Logout realizado com sucesso!', 'success')
    return redirect(url_for('prof.login'))

@prof_bp.route('/aulas')
@login_required
def aulas():
    # Verificar se o usuário é um professor
    if not session.get('professor_id'):
        flash('Acesso negado. Esta área é restrita para professores.', 'danger')
        return redirect(url_for('login'))
    
    # Obter o professor atual
    professor = Teacher.query.get(session['professor_id'])
    
    # Obter todas as aulas do professor
    aulas = QH.query.filter_by(professor=professor.nome_completo).all()
    
    dias_semana = {
        'segunda': 'Segunda-feira',
        'terca': 'Terça-feira',
        'quarta': 'Quarta-feira',
        'quinta': 'Quinta-feira',
        'sexta': 'Sexta-feira',
        'sabado': 'Sábado',
        'domingo': 'Domingo'
    }
    
    # Agrupar aulas por dia da semana
    aulas_por_dia = {}
    for dia in dias_semana:
        aulas_por_dia[dia] = []
    
    for aula in aulas:
        aulas_por_dia[aula.dia_da_semana].append(aula)
    
    # Ordenar aulas por horário
    for dia in aulas_por_dia:
        aulas_por_dia[dia].sort(key=lambda x: x.horario)
    
    return render_template(
        'professor/aulas.html',
        professor=professor,
        aulas_por_dia=aulas_por_dia,
        dias_semana=dias_semana,
        primary_collor=determinar_cor_professor()
    )

@prof_bp.route('/turma/<int:turma_id>')
@login_required
def turma_detalhes(turma_id):
    # Verificar se o usuário é um professor
    if not session.get('professor_id'):
        flash('Acesso negado. Esta área é restrita para professores.', 'danger')
        return redirect(url_for('login'))
    
    # Obter o professor atual
    professor = Teacher.query.get(session['professor_id'])
    
    # Obter a turma especificada
    turma = Turma.query.get_or_404(turma_id)
    
    # Verificar se o professor leciona para esta turma
    aulas_nesta_turma = QH.query.filter_by(
        professor=professor.nome_completo,
        turma_id=turma_id
    ).first()
    
    if not aulas_nesta_turma:
        flash('Você não tem acesso a esta turma.', 'danger')
        return redirect(url_for('prof.dashboard'))
    
    # Obter alunos da turma
    alunos = User.query.filter_by(turma_id=turma_id).order_by(User.nome_completo).all()
    
    # Obter materiais da turma
    materiais = Materia.query.filter_by(turma_id=turma_id).order_by(Materia.timestamp.desc()).all()
    
    return render_template(
        'professor/turma_detalhes.html',
        professor=professor,
        turma=turma,
        alunos=alunos,
        materiais=materiais,
        primary_collor=determinar_cor_professor()
    )

@prof_bp.route('/frequencia/<int:turma_id>', methods=['GET', 'POST'])
@login_required
def frequencia(turma_id):
    # Verificar se o usuário é um professor
    if not session.get('professor_id'):
        flash('Acesso negado. Esta área é restrita para professores.', 'danger')
        return redirect(url_for('login'))
    
    # Obter o professor atual
    professor = Teacher.query.get(session['professor_id'])
    
    # Obter a turma especificada
    turma = Turma.query.get_or_404(turma_id)
    
    # Verificar se o professor leciona para esta turma
    aulas_nesta_turma = QH.query.filter_by(
        professor=professor.nome_completo,
        turma_id=turma_id
    ).first()
    
    if not aulas_nesta_turma:
        flash('Você não tem acesso a esta turma.', 'danger')
        return redirect(url_for('prof.dashboard'))
    
    # Obter alunos da turma
    alunos = User.query.filter_by(turma_id=turma_id).order_by(User.nome_completo).all()
    
    # Obter a data atual
    data_atual = datetime.now(timezone('America/Sao_Paulo')).date()
    
    if request.method == 'POST':
        # Processar a frequência dos alunos
        for aluno in alunos:
            aluno_presente = request.form.get(f'presente_{aluno.id}') == 'on'
            aluno_justificado = request.form.get(f'justificado_{aluno.id}') == 'on'
            
            # Verificar se já existe registro para este aluno na data atual
            falta_existente = Falta.query.filter_by(
                user_id=aluno.id,
                data=data_atual,
                turma_id=turma_id
            ).first()
            
            if falta_existente:
                falta_existente.presente = aluno_presente
                falta_existente.falta_justificada = aluno_justificado
            else:
                nova_falta = Falta(
                    user_id=aluno.id,
                    data=data_atual,
                    presente=aluno_presente,
                    falta_justificada=aluno_justificado,
                    turma_id=turma_id
                )
                db.session.add(nova_falta)
        
        db.session.commit()
        flash('Frequência registrada com sucesso!', 'success')
        return redirect(url_for('prof.frequencia', turma_id=turma_id))
    
    # Obter registros de faltas existentes para a data atual
    faltas_existentes = {}
    for aluno in alunos:
        falta = Falta.query.filter_by(
            user_id=aluno.id,
            data=data_atual,
            turma_id=turma_id
        ).first()
        
        if falta:
            faltas_existentes[aluno.id] = {
                'presente': falta.presente,
                'justificado': falta.falta_justificada
            }
    
    return render_template(
        'professor/frequencia.html',
        professor=professor,
        turma=turma,
        alunos=alunos,
        faltas_existentes=faltas_existentes,
        data_atual=data_atual,
        primary_collor=determinar_cor_professor()
    )

@prof_bp.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    # Verificar se o usuário é um professor
    if not session.get('professor_id'):
        flash('Acesso negado. Esta área é restrita para professores.', 'danger')
        return redirect(url_for('login'))
    
    # Obter o professor atual
    professor = Teacher.query.get(session['professor_id'])
    
    if request.method == 'POST':
        nome_completo = request.form['nome_completo']
        email = request.form['email']
        senha_atual = request.form.get('senha_atual')
        nova_senha = request.form.get('nova_senha')
        confirmar_senha = request.form.get('confirmar_senha')
        imagem_perfil = request.files.get('imagem_perfil')
        
        # Validar email único (se estiver mudando o email)
        if email != professor.email and Teacher.query.filter_by(email=email).first():
            flash('Este email já está em uso por outro professor.', 'danger')
            return redirect(url_for('prof.perfil'))
        
        # Atualizar informações básicas
        professor.nome_completo = nome_completo
        professor.email = email
        
        # Processar alteração de senha, se solicitado
        if senha_atual and nova_senha and confirmar_senha:
            if not check_password_hash(professor.senha_hash, senha_atual):
                flash('Senha atual incorreta.', 'danger')
                return redirect(url_for('prof.perfil'))
            
            if nova_senha != confirmar_senha:
                flash('As novas senhas não coincidem.', 'danger')
                return redirect(url_for('prof.perfil'))
            
            professor.senha_hash = generate_password_hash(nova_senha)
            flash('Senha atualizada com sucesso!', 'success')
        
        # Processar imagem de perfil, se enviada
        if imagem_perfil:
            from app import save_profile_picture
            imagem_url = save_profile_picture(imagem_perfil)
            professor.imagem_url = imagem_url
        
        try:
            db.session.commit()
            flash('Perfil atualizado com sucesso!', 'success')
            return redirect(url_for('prof.perfil'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar perfil: {str(e)}', 'danger')
    
    return render_template(
        'professor/perfil.html',
        professor=professor,
        primary_collor=determinar_cor_professor()
    )


@prof_bp.route('/avisos/<int:turma_id>', methods=['GET', 'POST'])
@login_required
def avisos(turma_id):
    # Verificar se o usuário é um professor
    if not session.get('professor_id'):
        flash('Acesso negado. Esta área é restrita para professores.', 'danger')
        return redirect(url_for('login'))
    
    # Obter o professor atual
    professor = Teacher.query.get(session['professor_id'])
    
    # Obter a turma especificada
    turma = Turma.query.get_or_404(turma_id)
    
    # Verificar se o professor leciona para esta turma
    aulas_nesta_turma = QH.query.filter_by(
        professor=professor.nome_completo,
        turma_id=turma_id
    ).first()
    
    if not aulas_nesta_turma:
        flash('Você não tem acesso a esta turma.', 'danger')
        return redirect(url_for('prof.dashboard'))
    
    if request.method == 'POST':
        titulo = request.form['titulo']
        conteudo = request.form['conteudo']
        
        if titulo and conteudo:
            # Criar novo aviso
            novo_aviso = Aviso(
                titulo=titulo,
                conteudo=conteudo,
                autor=professor.nome_completo,
                timestamp=horario_atual_brasilia()
            )
            
            try:
                db.session.add(novo_aviso)
                db.session.flush()  # Para obter o ID do aviso
                
                # Associar o aviso à turma
                associacao = aviso_turma.insert().values(
                    aviso_id=novo_aviso.id,
                    turma_id=turma_id
                )
                db.session.execute(associacao)
                
                db.session.commit()
                flash('Aviso publicado com sucesso!', 'success')
                return redirect(url_for('prof.avisos', turma_id=turma_id))
            except Exception as e:
                db.session.rollback()
                flash(f'Erro ao publicar aviso: {str(e)}', 'danger')
    
    # Obter avisos da turma
    avisos = db.session.query(Aviso).join(
        aviso_turma,
        Aviso.id == aviso_turma.c.aviso_id
    ).filter(
        aviso_turma.c.turma_id == turma_id
    ).order_by(Aviso.timestamp.desc()).all()
    
    return render_template(
        'professor/avisos.html',
        professor=professor,
        turma=turma,
        avisos=avisos,
        primary_collor=determinar_cor_professor()
    )

@prof_bp.route('/relatorio/<int:turma_id>')
@login_required
def relatorio_turma(turma_id):
    # Verificar se o usuário é um professor
    if not session.get('professor_id'):
        flash('Acesso negado. Esta área é restrita para professores.', 'danger')
        return redirect(url_for('login'))
    
    # Obter o professor atual
    professor = Teacher.query.get(session['professor_id'])
    
    # Obter a turma especificada
    turma = Turma.query.get_or_404(turma_id)
    
    # Verificar se o professor leciona para esta turma
    aulas_nesta_turma = QH.query.filter_by(
        professor=professor.nome_completo,
        turma_id=turma_id
    ).first()
    
    if not aulas_nesta_turma:
        flash('Você não tem acesso a esta turma.', 'danger')
        return redirect(url_for('prof.dashboard'))
    
    # Obter alunos da turma
    alunos = User.query.filter_by(turma_id=turma_id).order_by(User.nome_completo).all()
    
    # Obter estatísticas de frequência
    estatisticas = []
    for aluno in alunos:
        total_faltas = Falta.query.filter_by(
            user_id=aluno.id,
            turma_id=turma_id,
            presente=False
        ).count()
        
        faltas_justificadas = Falta.query.filter_by(
            user_id=aluno.id,
            turma_id=turma_id,
            presente=False,
            falta_justificada=True
        ).count()
        
        # Calcular porcentagem de presença
        total_aulas = Falta.query.filter_by(
            user_id=aluno.id,
            turma_id=turma_id
        ).count()
        
        porcentagem_presenca = 0
        if total_aulas > 0:
            presencas = total_aulas - total_faltas
            porcentagem_presenca = (presencas / total_aulas) * 100
        
        estatisticas.append({
            'aluno': aluno,
            'total_faltas': total_faltas,
            'faltas_justificadas': faltas_justificadas,
            'porcentagem_presenca': round(porcentagem_presenca, 2)
        })
    
    return render_template(
        'professor/relatorio_turma.html',
        professor=professor,
        turma=turma,
        estatisticas=estatisticas,
        primary_collor=determinar_cor_professor()
    )

@prof_bp.route('/')
def index():
    return render_template('professor/welcome.html')

@prof_bp.route('/materiais/adicionar/<int:turma_id>', methods=['GET', 'POST'])
@login_required
def adicionar_material(turma_id):
    # Verificar se o usuário é um professor
    if not session.get('professor_id'):
        flash('Acesso negado. Esta área é restrita para professores.', 'danger')
        return redirect(url_for('login'))
    
    # Obter o professor atual
    professor = Teacher.query.get(session['professor_id'])
    
    # Obter a turma especificada
    turma = Turma.query.get_or_404(turma_id)
    
    # Verificar se o professor leciona para esta turma
    aulas_nesta_turma = QH.query.filter_by(
        professor=professor.nome_completo,
        turma_id=turma_id
    ).first()
    
    if not aulas_nesta_turma:
        flash('Você não tem acesso a esta turma.', 'danger')
        return redirect(url_for('prof.dashboard'))
    
    if request.method == 'POST':
        # Processar o material enviado
        nome_material = request.form['nome_material']
        descricao_material = request.form['descricao_material']
        arquivo = request.files.get('arquivo')
        
        if not nome_material or not descricao_material:
            flash('Por favor, preencha todos os campos obrigatórios.', 'danger')
            return redirect(url_for('prof.adicionar_material', turma_id=turma_id))
        
        # Processar o arquivo, se houver
        if arquivo:
            # Gerar um nome único para o arquivo
            nome_arquivo = f"{uuid.uuid4().hex}_{arquivo.filename}"
            arquivo.save(f'uploads/{nome_arquivo}')
            
            # Criar um novo material
            novo_material = Materia(
                nome=nome_material,
                descricao=descricao_material,
                arquivo=nome_arquivo,
                turma_id=turma_id,
                professor_id=professor.id,
                timestamp=datetime.now()
            )
            
            try:
                db.session.add(novo_material)
                db.session.commit()
                flash('Material adicionado com sucesso!', 'success')
                return redirect(url_for('prof.turma_detalhes', turma_id=turma_id))
            except Exception as e:
                db.session.rollback()
                flash(f'Erro ao adicionar material: {str(e)}', 'danger')
                return redirect(url_for('prof.adicionar_material', turma_id=turma_id))
    
    return render_template(
        'professor/adicionar_material.html',
        professor=professor,
        turma=turma,
        primary_collor=determinar_cor_professor()
    )
