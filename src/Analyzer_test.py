import os
import time
import xml.etree.ElementTree as ET
from modules.DeepLink import DeepLinkAnalyzer
from modules.WebView import WebViewAnalyzer
from modules.Hardcoded import HardCodedAnalyzer
from modules.SQL_Injection import SQLInjectionAnalyzer
from modules.Permission import PermissionAnalyzer
from views.web_generator import save_findings_as_html

class Analyzer_test:
    def __init__(self, java_dir='java_src', smali_dir='smali_src'):
        self.java_dir = java_dir
        self.smali_dir = smali_dir

        self.sql_injection_analyzer = SQLInjectionAnalyzer(self.java_dir)
        self.normal_analyzer = [
            (HardCodedAnalyzer(), ['.xml']),
            (WebViewAnalyzer(), ['.java', '.xml']),
            (PermissionAnalyzer(), ['.xml']),
        ]
        self.smali_analyzers = [
            (DeepLinkAnalyzer(), ['.smali', '.xml']),
        ]

    def analyze_file(self, file_path, analyzers, smali_dir=None):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            findings = []
            for analyzer, extensions in analyzers:
                if any(file_path.endswith(ext) for ext in extensions):
                    if isinstance(analyzer, DeepLinkAnalyzer) and smali_dir:
                        if "original" in file_path:
                            continue
                        result = analyzer.run(content, smali_dir)
                    else:
                        result = analyzer.run(content)
                    if result:
                        findings.append((file_path, analyzer.__class__.__name__, result))
            return findings
        
    def process_directory(self, all_findings, header, directory, analyzers, target_files=None, smali_dir=None):
        print(analyzers)
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if any(file.endswith(ext) for _, exts in analyzers for ext in exts):
                    if target_files:
                        if file not in target_files:
                            continue
                    findings = self.analyze_file(file_path, analyzers, smali_dir)
                    if findings:
                        package_name = root.replace(directory, '').strip(os.sep).split(os.sep)[0]
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

        # 1. SQLInjectionAnalyzer는 모든 .java 파일 검사
        self.process_directory(all_findings, header, self.java_dir, [(self.sql_injection_analyzer, ['.java'])])

        # 2. 다른 분석기들은 특정 xml 파일만 검사
        target_xml_files = ["AndroidManifest.xml", "strings.xml"]

        self.process_directory(all_findings, header, self.java_dir, self.normal_analyzer, target_files=target_xml_files)
        self.process_directory(all_findings, header, self.smali_dir, self.smali_analyzers, target_files=["AndroidManifest.xml"], smali_dir=self.smali_dir)

        if all_findings:
            save_findings_as_html(all_findings)

if __name__ == "__main__":
    # 성능 측정 위해서 추가
    start = time.time()
    analyzer = Analyzer_test()
    analyzer.run()
    print(f"Execution time: {time.time() - start:.2f} seconds")
