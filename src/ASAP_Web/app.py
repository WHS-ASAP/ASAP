import os
from flask import Flask
from views import main
from database import db  # db import 추가

def create_app():
    # src/instance 경로에 데이터베이스 파일 생성
    base_dir = os.path.abspath(os.path.dirname(__file__))
    templates_dir = os.path.join(base_dir, 'templates')

    app = Flask(__name__, template_folder=templates_dir)
    
    instance_path = os.path.join(base_dir, '..', 'instance')
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)
    else:
        print("instance path exists")
    
    # 데이터베이스 URI 설정
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(instance_path, 'result.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    app.register_blueprint(main)
    
    # SQLAlchemy 초기화
    db.init_app(app)  # db 객체를 app에 초기화
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
