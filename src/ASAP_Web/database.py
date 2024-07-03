# ASAP_Web/database.py

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Result(db.Model):
    __tablename__ = 'results'

    id = db.Column(db.Integer, primary_key=True)
    package_name = db.Column(db.String(255))
    file_path = db.Column(db.String(255))
    vuln_type = db.Column(db.String(255))
    risk = db.Column(db.String(255))
    result = db.Column(db.Text)
    timestamp = db.Column(db.Text)

def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()

    def __init__(self, package_name, file_path, vuln_type, risk, result, timestamp):
        self.package_name = package_name
        self.file_path = file_path
        self.vuln_type = vuln_type
        self.risk = risk
        self.result = result
        self.timestamp = timestamp

def save_finding_to_db(package_name, file_path, vuln_type, risk, result, timestamp):
    finding = Result(package_name=package_name, file_path=file_path, vuln_type=vuln_type, risk=risk, result=result, timestamp=timestamp)
    db.session.add(finding)
    db.session.commit()


