import re

class SQLInjectionAnalyzer:
    def __init__(self, java_dir):
        self.java_dir = java_dir
        self.provider_pattern = re.compile(r"extends ContentProvider", re.IGNORECASE)
        # exeSQL, rawQuery 사용 패턴
        self.sql_injection_pattern_1 = re.compile(r"(\bexecSQL\b|\brawQuery\b)\(.*?['\"].*?['\"].*?\)", re.IGNORECASE)
        # 인젝션 가능할만한 문구 세가지 패턴 추가  ex1. ' +   ex2. = ?
        self.sql_injection_pattern_2 = re.compile(r"\"\s*\+|'\s*\+|\=\s*\?", re.IGNORECASE)
        # 사용자 입력 검증 및 이스케이프 처리문 
        self.input_validation_pattern = re.compile(r"Pattern\.matches\(.*?\)|.*?\.replaceAll\(.*?\)|.*?\.replace\(.*?\)", re.IGNORECASE)
        # ORM 라이브러리
        self.orm_pattern = re.compile(r"@Dao|@Entity|@Database|@Query", re.IGNORECASE)
        # PreparedStatement, ContentValues 패턴
        self.prepared_statement_pattern = re.compile(r"\.compileStatement\(.*?\)|PreparedStatement|.*?\?.*?\)|ContentValues", re.IGNORECASE)
        # SQLi 취약점들중 공통적으로 많이 발견된 외부 패키지 패턴
        self.external_package_pattern = re.compile(r"package\s+(com\.google\.|androidx\.|com\.android\.)|import com\.instabug\.library\.model\.session\.SessionParameter;", re.IGNORECASE)
        # 추가 패턴 : "import android.database.sqlite.SQLiteOpenHelper;" && " + System.currentTimeMillis() + "
        self.additional_pattern = re.compile(r"\+ System\.currentTimeMillis\(\) \+" + r"|import android\.database\.sqlite\.SQLiteOpenHelper;", re.IGNORECASE)

    def is_content_provider(self, file_path):
        # 파일 내에서 ContentProvider 관련 코드가 있는지 검사
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            return self.provider_pattern.search(content) is not None
        except UnicodeDecodeError:
            return False

    def is_external_package(self, content):
        # 외부 패키지를 사용하는지 검사
        return self.external_package_pattern.search(content) is not None

    def analyze_file(self, content):
        # 파일에서 SQL 취약점을 검사
        findings = []
        if not self.is_external_package(content):
            matches = self.sql_injection_pattern_1.findall(content) and self.sql_injection_pattern_2.findall(content)
            if matches:
                # SQL Injection을 예방하는 코드가 있나 검사
                if not self.input_validation_pattern.search(content) and not self.orm_pattern.search(content) and not self.prepared_statement_pattern.search(content) and not self.additional_pattern.search(content):
                    findings.append("Potential SQL Injection vulnerabilities found")
        return findings

    def run(self, content):
        return self.analyze_file(content)