import os
import sys
from hardcoding_pattern import ApiKeyAnalyzer, FirebaseDatabaseAnalyzer
from DeepLink import DeepLinkAnalyzer

# 'views' 디렉토리를 모듈 검색 경로에 추가
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../views')))
from web_generator import save_findings_as_html

class Analyzer:
    def __init__(self, java_dir='java_src'):
        self.java_dir = java_dir
        self.analyzers = [ApiKeyAnalyzer(), FirebaseDatabaseAnalyzer(), DeepLinkAnalyzer()]

    def analyze_file(self, file_path):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            findings = []
            for analyzer in self.analyzers:
                result = analyzer.run(content)
                if result:
                    findings.append((file_path, result))
            return findings

    def run(self):
        if not os.path.exists(self.java_dir):
            print(f"Error: Java source directory '{self.java_dir}' not found.")
            return

        all_findings = {}
        header = ["File", "Issue"]
        for root, dirs, files in os.walk(self.java_dir):
            for file in files:
                if file.endswith(".java") or file.endswith(".xml"):
                    file_path = os.path.join(root, file)
                    findings = self.analyze_file(file_path)
                    if findings:
                        # 최상위 패키지 이름을 추출
                        package_name = root.replace(self.java_dir, '').strip(os.sep).split(os.sep)[0]
                        if package_name not in all_findings:
                            all_findings[package_name] = []
                        for finding in findings:
                            all_findings[package_name].append({header[0]: finding[0], header[1]: finding[1]})

        if all_findings:
            save_findings_as_html(all_findings)

if __name__ == "__main__":
    analyzer = Analyzer()
    analyzer.run()
