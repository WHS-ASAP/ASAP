import re

class SQLInjectionAnalyzer:
    
    def __init__(self, java_dir):
        self.java_dir = java_dir
        self.provider_pattern = re.compile(r"extends ContentProvider", re.IGNORECASE)
        self.sql_injection_pattern = re.compile(r"(\bexecSQL\b|\brawQuery\b)\(.*?['\"].*?['\"].*?\)", re.IGNORECASE)

    def is_content_provider(self, file_path):
        # 파일 내에서 ContentProvider 관련 코드가 있는지 검사
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                return self.provider_pattern.search(content) is not None
        except UnicodeDecodeError:
            return False

    def analyze_file(self, content):
        # 파일에서 SQL 취약점을 검사
        findings = []
        matches = self.sql_injection_pattern.findall(content)
        if matches:
            findings.append("Potential SQL Injection vulnerabilities found")
        return findings

    def run(self, content):
        return self.analyze_file(content)