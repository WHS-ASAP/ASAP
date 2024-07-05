from flask import Blueprint, render_template, jsonify
from database import db, Result

main = Blueprint('main', __name__)

@main.route('/')
def index():
    packages = db.session.query(Result.package_name).distinct().all()
    return render_template('index.html', packages=[pkg[0] for pkg in packages])

@main.route('/package/<package_name>')
def package_results(package_name):
    results = Result.query.filter_by(package_name=package_name).all()
    return render_template('results.html', package_name=package_name, results=results)

@main.route('/module/<package_name>/<analyzer>')
def module_results(package_name, analyzer):
    results = Result.query.filter_by(package_name=package_name, analyzer=analyzer).all()
    return render_template('module_results.html', package_name=package_name, analyzer=analyzer, results=results)

@main.route('/api/vulnerability-counts')
def get_vulnerability_counts():
    counts = db.session.query(Result.package_name, db.func.count(Result.id)).group_by(Result.package_name).all()
    data = {
        'packages': [result[0] for result in counts],
        'counts': [result[1] for result in counts]
    }
    return jsonify(data)

@main.route('/api/vulnerability-trend')
def get_vulnerability_trend():
    results = db.session.query(Result.package_name, Result.vuln_type, db.func.count(Result.id)).group_by(Result.package_name, Result.vuln_type).all()
    data = {}
    for package_name, vuln_type, count in results:
        if package_name not in data:
            data[package_name] = {}
        data[package_name][vuln_type] = count
    return jsonify(data)

@main.route('/api/vulnerability-by-type')
def get_vulnerability_by_type():
    results = db.session.query(Result.vuln_type, db.func.count(Result.id)).group_by(Result.vuln_type).all()
    data = {
        'vuln_types': [result[0] for result in results],
        'counts': [result[1] for result in results]
    }
    return jsonify(data)

@main.route('/api/history_table')
def history_table():
    packages = db.session.query(Result.package_name).distinct().all()

    package_data = []
    for package in packages:
        package_name = package[0]
        # 가장 높은 위험도를 가진 결과를 가져옵니다.
        highest_risk_result = db.session.query(Result).filter_by(package_name=package_name).order_by(
            db.case(
                (Result.risk == 'High', 1),
                (Result.risk == 'Medium', 2),
                (Result.risk == 'Low', 3)
            )
        ).first()
        if highest_risk_result:
            package_data.append({
                'package_name': highest_risk_result.package_name,
                'platform': 'apk',
                'type': 'auto',
                'created_at': highest_risk_result.timestamp,
                'risk': highest_risk_result.risk
            })

    return jsonify(package_data)