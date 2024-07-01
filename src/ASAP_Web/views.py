import sys
import os
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
