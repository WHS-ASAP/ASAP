# ASAP_Web/database.py

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Result(db.Model):
    __tablename__ = 'results'

    id = db.Column(db.Integer, primary_key=True)
    package_name = db.Column(db.String(255))
    file_path = db.Column(db.String(255))
    analyzer = db.Column(db.String(255))
    result = db.Column(db.Text)

def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()

    def __init__(self, package_name, file_path, analyzer, result):
        self.package_name = package_name
        self.file_path = file_path
        self.analyzer = analyzer
        self.result = result

def save_finding_to_db(package_name, file_path, analyzer, result):
    finding = Result(package_name=package_name, file_path=file_path, analyzer=analyzer, result=result)
    db.session.add(finding)
    db.session.commit()


