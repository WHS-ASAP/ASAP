import os
import time
from modules.DeepLink import DeepLinkAnalyzer
from modules.WebView import WebViewAnalyzer
from modules.Hardcoded import HardCodedAnalyzer
from modules.SQL_Injection import SQLInjectionAnalyzer
from modules.Permission import PermissionAnalyzer
from modules.Crypto import CryptoAnalyzer
from modules.LogE import LogAnalyzer
from modules.utils import FilePathCheck
from ASAP_Web import create_app
from ASAP_Web.database import db, save_finding_to_db, Result

app = create_app()

# make dictionary Analyzer - vuln_type
vuln_types = {
    "SQLInjectionAnalyzer": "SQL_Injection", 
    "LogAnalyzer": "LogE", 
    "HardCodedAnalyzer": "Hardcoded",
    "DeepLinkAnalyzer": "DeepLink", 
    "WebViewAnalyzer": "WebView", 
    "CryptoAnalyzer": "Crypto", 
    "PermissionAnalyzer": "Permission"
}

# 기준: 결과값과 취약점까지의 거리/해커원 cvss 기준 / 해커원에서 관련 사례들의 risk책정값  
risk_levels = {
    "SQLInjectionAnalyzer": "High", 
    "LogAnalyzer": "High", 
    "HardCodedAnalyzer": "High",
    "DeepLinkAnalyzer": "Medium", 
    "WebViewAnalyzer": "Medium", 
    "CryptoAnalyzer": "Medium", 
    "PermissionAnalyzer": "Low"
}

class AnalyzerTest:
    def __init__(self, java_dir='java_src', smali_dir='smali_src'):
        self.java_dir = java_dir
        self.smali_dir = smali_dir

        self.analyzers = {
            'java': [
                (SQLInjectionAnalyzer(), ['.java']), 
                (CryptoAnalyzer(), ['.java']), 
                (LogAnalyzer(), ['.java'])
            ],
            'xml': [
                (PermissionAnalyzer(), ['.xml']), 
                (WebViewAnalyzer(), ['.xml']), 
                (HardCodedAnalyzer(), ['.xml', '.java'])
            ],
            'smali': [
                (DeepLinkAnalyzer(), ['.smali', '.xml'])
            ]
        }

    def analyze_file(self, file_path, analyzers, now_time, smali_dir=None, package_name=None):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            findings = []
            for analyzer, extensions in analyzers:
                result = []
                if any(file_path.endswith(ext) for ext in extensions):
                    if isinstance(analyzer, DeepLinkAnalyzer) and smali_dir:
                        if "original" in file_path:
                            continue
                        result = analyzer.run(content, smali_dir)
                    elif isinstance(analyzer, CryptoAnalyzer):
                        if FilePathCheck(file_path).validate():
                            result = analyzer.run(content)
                    else:
                        result = analyzer.run(content)
                    
                    if result:
                        findings.append((file_path, analyzer.__class__.__name__, result))
                        package_name = package_name.split(os.sep)[-1]
                        with app.app_context():
                            save_finding_to_db(package_name, file_path, 
                                               vuln_types[analyzer.__class__.__name__],
                                               risk_levels[analyzer.__class__.__name__], 
                                               str(result), now_time)
            return findings

    def process_directory(self, directory, analyzers, now_time, target_files=None):
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if any(file.endswith(ext) for _, exts in analyzers for ext in exts):
                    if target_files and file not in target_files:
                        continue
                    self.analyze_file(file_path, analyzers, now_time, 
                                      directory if any(ext == '.smali' for _, exts in analyzers for ext in exts) else None, 
                                      directory)

    def process_root_directory(self, root_directory, analyzers, now_time, package_names_to_skip, target_files=None):
        for package_name in os.listdir(root_directory):
            package_path = os.path.join(root_directory, package_name)
            package_name = package_path.replace(root_directory, '').strip(os.sep).split(os.sep)[0]
            # print(package_name)
            time.sleep(0.2)
            if package_name not in package_names_to_skip:
                self.process_directory(package_path, analyzers, now_time, target_files)
            else:
                print(f"Skipping already analyzed package: {package_name}")

    def run(self):
        if not os.path.exists(self.java_dir) or not os.path.exists(self.smali_dir):
            print(f"Error: Source directory '{self.java_dir}' or '{self.smali_dir}' not found.")
            return

        with app.app_context():
            db.create_all()

        now_time = time.strftime("%B %d %Y")

        package_names_to_skip = self.get_analyzed_package_names()
        print("already analyzed package: ", package_names_to_skip)

        self.process_root_directory(self.java_dir, self.analyzers['java'], now_time, package_names_to_skip)
        self.process_root_directory(self.java_dir, self.analyzers['xml'], now_time, package_names_to_skip, ["AndroidManifest.xml", "strings.xml"])
        self.process_root_directory(self.smali_dir, self.analyzers['smali'], now_time, package_names_to_skip, ["AndroidManifest.xml"])

    def get_analyzed_package_names(self):
        with app.app_context():
            return {result.package_name for result in Result.query.with_entities(Result.package_name).distinct()}

if __name__ == "__main__":
    start_time = time.time()
    analyzer = AnalyzerTest()
    analyzer.run()
    print(f"Execution time: {time.time() - start_time:.2f} seconds")