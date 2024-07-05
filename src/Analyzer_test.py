import os
import time
from modules.DeepLink import DeepLinkAnalyzer
from modules.WebView import WebViewAnalyzer
from modules.Hardcoded import HardCodedAnalyzer
from modules.SQL_Injection import SQLInjectionAnalyzer
from modules.Permission import PermissionAnalyzer
from modules.Crypto import CryptoAnalyzer
from modules.utils import FilePathCheck
from ASAP_Web import create_app
from ASAP_Web.database import db, save_finding_to_db

app = create_app()

# make dictionary Analyzer - vuln_type
vuln_types = {"SQLInjectionAnalyzer": "SQL_Injection", "LogEAnalyzer": "LogE", "HardCodedAnalyzer": "Hardcoded",
              "DeepLinkAnalyzer": "DeepLink", "WebViewAnalyzer": "WebView", "CryptoAnalyzer": "Crypto", 
              "PermissionAnalyzer": "Permission"}

# 기준: 결과값과 취약점까지의 거리/해커원 cvss 기준 / 해커원에서 관련 사례들의 risk책정값  
risk_levels = {"SQLInjectionAnalyzer": "High", "LogEAnalyzer": "High", "HardCodedAnalyzer": "High",
                "DeepLinkAnalyzer": "Medium", "WebViewAnalyzer": "Medium", "CryptoAnalyzer": "Medium", 
                "PermissionAnalyzer": "Low"}



class AnalyzerTest:
    def __init__(self, java_dir='java_src', smali_dir='smali_src'):
        self.java_dir = java_dir
        self.smali_dir = smali_dir

        self.analyzers = {
            'java': [(SQLInjectionAnalyzer(), ['.java']), (CryptoAnalyzer(), ['.java'])],
            'xml': [(PermissionAnalyzer(), ['.xml']), (WebViewAnalyzer(), ['.xml']), (HardCodedAnalyzer(), ['.xml', '.java'])],
            'smali': [(DeepLinkAnalyzer(), ['.smali', '.xml'])]
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
                        with app.app_context():
                            
                            save_finding_to_db(package_name, file_path, vuln_types[analyzer.__class__.__name__]
                                               , risk_levels[analyzer.__class__.__name__], str(result), now_time)
            
            return findings

    def process_directory(self, directory, analyzers, now_time, target_files=None):
        for root, _, files in os.walk(directory):
            package_name = root.replace(directory, '').strip(os.sep).split(os.sep)[0]
            for file in files:
                file_path = os.path.join(root, file)
                if any(file.endswith(ext) for _, exts in analyzers for ext in exts):
                    if target_files and file not in target_files and file.endswith('.xml'):
                        continue
                    self.analyze_file(file_path, analyzers, now_time
                                      , directory if any(ext == '.smali' for _, exts in analyzers for ext in exts) else None, package_name)

    def run(self):
        if not os.path.exists(self.java_dir) or not os.path.exists(self.smali_dir):
            print(f"Error: Source directory '{self.java_dir}' or '{self.smali_dir}' not found.")
            return


        with app.app_context():
            db.create_all()

        now_time = time.strftime("%B %d %Y")
        
        self.process_directory(self.java_dir, self.analyzers['java'], now_time)
        self.process_directory(self.java_dir, self.analyzers['xml'], now_time, ["AndroidManifest.xml", "strings.xml"])
        self.process_directory(self.smali_dir, self.analyzers['smali'], now_time, ["AndroidManifest.xml"])

if __name__ == "__main__":
    start_time = time.time()
    analyzer = AnalyzerTest()
    analyzer.run()
    print(f"Execution time: {time.time() - start_time:.2f} seconds")
