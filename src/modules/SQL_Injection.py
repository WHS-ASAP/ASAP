import re
from modules.utils import ExtractContent


class SQLInjectionAnalyzer:
    def __init__(self):
        self.provider_pattern = re.compile(r"extends ContentProvider", re.IGNORECASE)
        self.sql_injection_pattern_1 = re.compile(
            r"(\bexecSQL\b|\brawQuery\b)\(.*?['\"].*?['\"].*?\)", re.IGNORECASE
        )
        self.sql_injection_pattern_2 = re.compile(
            r"\"\s*\+|'\s*\+|\=\s*\?", re.IGNORECASE
        )
        self.input_validation_pattern = re.compile(
            r"Pattern\.matches\(.*?\)|.*?\.replaceAll\(.*?\)|.*?\.replace\(.*?\)",
            re.IGNORECASE,
        )
        self.orm_pattern = re.compile(r"@Dao|@Entity|@Database|@Query", re.IGNORECASE)
        self.prepared_statement_pattern = re.compile(
            r"\.compileStatement\(.*?\)|PreparedStatement|.*?\?.*?\)|ContentValues",
            re.IGNORECASE,
        )
        self.external_package_pattern = re.compile(
            r"package\s+(com\.google\.|androidx\.|com\.android\.)|import\s+(com\.instabug\.library\.model\.session\.SessionParameter|androidx\.room\.)",
            re.IGNORECASE,
        )
        self.additional_pattern = re.compile(
            r"\+ System\.currentTimeMillis\(\) \+"
            + r"|import android\.database\.sqlite\.SQLiteOpenHelper;",
            re.IGNORECASE,
        )

    def is_content_provider(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                content = file.read()
            return self.provider_pattern.search(content) is not None
        except UnicodeDecodeError:
            return False

    def extract_sql_injection_lines(self, content):
        lines = content.split("\n")
        result = []
        for line_num, line in enumerate(lines, start=1):
            if self.sql_injection_pattern_1.search(
                line
            ) and self.sql_injection_pattern_2.search(line):
                result.append((line_num, line))
        return result

    def is_external_package(self, content):
        return self.external_package_pattern.search(content) is not None

    def has_prevention_pattern(self, content):
        return (
            self.input_validation_pattern.search(content)
            or self.orm_pattern.search(content)
            or self.prepared_statement_pattern.search(content)
            or self.additional_pattern.search(content)
        )

    def analyze_file(self, content):
        if self.is_external_package(content):
            return []

        sql_injection_lines = self.extract_sql_injection_lines(content)
        if sql_injection_lines and not self.has_prevention_pattern(content):
            return sql_injection_lines

        return []

    def run(self, file_path):
        accessible_file_types = ["java", "kt"]
        if not file_path.endswith(tuple(accessible_file_types)):
            # print(f"LogAnalyzer: {file_path} is not a java or kotlin file")
            return
        else:
            content = ExtractContent(file_path).extract_content()

        return self.analyze_file(content)


if __name__ == "__main__":
    pass
