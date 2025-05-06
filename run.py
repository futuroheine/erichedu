from app import app, db
from professor import prof_bp


app.register_blueprint(prof_bp, url_prefix='/professor')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Certifica-se de que as tabelas do banco existem
    app.run(debug=False)
