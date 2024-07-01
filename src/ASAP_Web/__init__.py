# ASAP/src/ASAP_Web/__init__.py

from flask import Flask
from ASAP_Web.database import init_db
# from ASAP_Web.views import main

def create_app():
    print("Creating Flask app...")
    app = Flask(__name__)
    
    # Flask 애플리케이션의 기본 설정 추가
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///result.db'  # 현재 디렉토리에 result.db 생성
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # 데이터베이스 초기화
    init_db(app)
    
    # Blueprint 등록
    # app.register_blueprint(main)
    
    return app