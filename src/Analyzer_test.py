# Analyzer_test.py

import os
import sys
import time

# 현재 파일의 디렉토리를 기준으로 최상위 디렉토리를 찾습니다.
# sys.path.append(os.path.dirname(os.path.abspath(__file__)).rsplit('/', 1)[0])

from modules.DeepLink import DeepLinkAnalyzer
from modules.WebView import WebViewAnalyzer
from modules.Hardcoded import HardCodedAnalyzer
from modules.SQL_Injection import SQLInjectionAnalyzer
from modules.Permission import PermissionAnalyzer
from modules.Crypto import CryptoAnalyzer
from modules.utils import FilePathCheck
from views.web_generator import save_findings_as_html
from ASAP_Web import create_app
from ASAP_Web.database import db, save_finding_to_db

# Flask 애플리케이션 초기화
app = create_app()

class Analyzer_test:
    def __init__(self, java_dir='java_src', smali_dir='smali_src'):
        self.java_dir = java_dir
        self.smali_dir = smali_dir

        self.java_analyzer = [
            (SQLInjectionAnalyzer(), ['.java']),
            (CryptoAnalyzer(), ['.java']),
        ]

        self.xml_analyzer = [
            (HardCodedAnalyzer(), ['.xml']),
            (PermissionAnalyzer(), ['.xml']),
            (WebViewAnalyzer(), ['.xml']),
        ]

        self.java_xml_analyzer = [
            (WebViewAnalyzer(), ['.java', '.xml']),
        ]

        self.smali_analyzers = [
            (DeepLinkAnalyzer(), ['.smali', '.xml']),
        ]

    def analyze_file(self, file_path, analyzers, smali_dir=None, package_name=None):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            findings = []
            result = []
            for analyzer, extensions in analyzers:
                if any(file_path.endswith(ext) for ext in extensions):
                    if isinstance(analyzer, DeepLinkAnalyzer) and smali_dir:
                        if "original" in file_path:
                            continue
                        result = analyzer.run(content, smali_dir)
                    elif isinstance(analyzer, CryptoAnalyzer):
                        file_checker = FilePathCheck(file_path)
                        if file_checker.validate():
                            result = analyzer.run(content)
                    else:
                        result = analyzer.run(content)
                    if result:
                        findings.append((file_path, analyzer.__class__.__name__, result))
                        # Flask 애플리케이션 컨텍스트 내에서 데이터베이스에 저장
                        with app.app_context():
                            save_finding_to_db(package_name, file_path, analyzer.__class__.__name__, str(result))
            return findings
        
    def process_directory(self, all_findings, header, directory, analyzers, target_files=None):
        print(analyzers)
        
        for root, dirs, files in os.walk(directory):
            # 여기서 root에서 directory를 ''로 만들고 package name 추출하는게 더 나을듯 그리고
            package_name = root.replace(directory, '').strip(os.sep).split(os.sep)[0]
            # 여기서 이미 분석해서 result.db에 저장된 package name들을 뽑아와서 그것과 비교해서
            # 새로운 package name이면 추가하고 아니면 넘어가는 식으로 구현하기
            for file in files:
                file_path = os.path.join(root, file)
                if any(file.endswith(ext) for _, exts in analyzers for ext in exts):
                    if target_files:
                        if file not in target_files:
                            continue
                    findings = self.analyze_file(file_path, analyzers, directory, package_name)
                    if findings:
                        if package_name not in all_findings:
                            all_findings[package_name] = []
                        for finding in findings:
                            all_findings[package_name].append({header[0]: finding[0], header[1]: finding[1], header[2]: finding[2]})

    def run(self):
        if not os.path.exists(self.java_dir):
            print(f"Error: Java source directory '{self.java_dir}' not found.")
            return
    
        if not os.path.exists(self.smali_dir):
            print(f"Error: smali source directory '{self.smali_dir}' not found.")
            return

        all_findings = {}
        header = ["File", "Issue", "Result"]

        # SQLAlchemy의 create_all 직접 호출
        with app.app_context():
            db.create_all()

        # 1. SQLInjectionAnalyzer, CryptoAnalyzer는 모든 .java 파일 검사
        self.process_directory(all_findings, header, self.java_dir, self.java_analyzer)

        # 2. 다른 분석기들은 특정 xml 파일만 검사
        target_xml_files = ["AndroidManifest.xml", "strings.xml"]
        self.process_directory(all_findings, header, self.java_dir, self.xml_analyzer, target_files=target_xml_files)

        self.process_directory(all_findings, header, self.java_dir, self.java_xml_analyzer, target_files=target_xml_files)

        self.process_directory(all_findings, header, self.smali_dir, self.smali_analyzers, target_files=["AndroidManifest.xml"])

        if all_findings:
            save_findings_as_html(all_findings)

if __name__ == "__main__":
    # Analyzer_test.py를 직접 실행할 때만 작동
    start = time.time()
    analyzer = Analyzer_test()
    analyzer.run()
    print(f"Execution time: {time.time() - start:.2f} seconds")