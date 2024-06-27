import os
import sys
from modules.Firebase import FirebaseDatabaseAnalyzer
from modules.DeepLink import DeepLinkAnalyzer
from modules.Hardcoded import HardCodedAnalyzer
from views.web_generator import save_findings_as_html


class Analyzer_test:
    def __init__(self, java_dir='java_src'):
        self.java_dir = java_dir
        # 각 분석기에 적용할 파일 확장자를 지정할 수 있도록 확장자 정보를 포함
        self.analyzers = [
            (FirebaseDatabaseAnalyzer(), ['.xml']),
            (DeepLinkAnalyzer(), ['.java', '.xml']),
            (HardCodedAnalyzer(), ['.xml']),
        ]

    def analyze_file(self, file_path):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            findings = []
            for analyzer, extensions in self.analyzers:
                if any(file_path.endswith(ext) for ext in extensions):  # 파일 확장자가 분석기에 적합한지 확인
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
    analyzer = Analyzer_test()
    analyzer.run()
