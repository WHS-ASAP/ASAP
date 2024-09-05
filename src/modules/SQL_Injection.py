import re, os
from modules.utils import ExtractContent


class ContentProviderAnalyzer:

    def __init__(self):
        self.provider_pattern = re.compile(
            r'<provider[^<>]*exported="true"[^<>]*', re.IGNORECASE
        )
        self.name_pattern = re.compile(
            r'android:name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE
        )
        # 우선 Uri.parse("content://")가 아니라 Uri.parse()에서 ()사이에 있는 값을 추출
        self.uriParse_pattern = re.compile(
            r'Uri\.parse\(["\'](.*?)["\']\)', re.IGNORECASE
        )
        # self.uriParse_pattern = re.compile(r'Uri\.parse\(["\']content://', re.IGNORECASE)
        self.uriMatcher_pattern = re.compile(
            r"addURI\(([^,]+),\s*([^,]+),\s*[0-9]+\)",
            re.IGNORECASE,
        )
        # 상수 선언 패턴
        self.constant_uri_pattern = re.compile(
            r'static\s+final\s+String\s+[\w_]+\s*=\s*["\'](content://[^"\']+)["\']',
            re.IGNORECASE,
        )

        # 변수 할당 패턴
        self.variable_assignment_pattern = re.compile(
            r'(\w+)\s*=\s*["\'](.*?)["\']', re.IGNORECASE
        )

    def exported_activity(self, content):
        matches = self.provider_pattern.findall(content)
        provider_name = []
        for match in matches:
            name_match = self.name_pattern.search(match)
            if name_match:
                provider_name.append(name_match.group(1))
        print(provider_name)
        return provider_name

    def extract_contentURI(self, sus_content):
        # 전체 추출한 Content URI 리스트
        content_uri_lst = []

        # 1-1. Uri.parse()에서 () 사이의 값을 추출
        uri_parse_match = self.uriParse_pattern.search(sus_content)
        if uri_parse_match:
            uri_value = uri_parse_match.group(1)
            if not uri_value.startswith(
                ("'", '"')
            ):  # 따옴표로 감싸져 있지 않으면 변수로 판단
                # 변수명을 기반으로 해당 값 할당 추적
                # 1-2. URI = "content://~"와 같이 변수에 저장후, Uri.parse로 사용하는 경우
                uri_value = self.find_variable_value(uri_value, sus_content)
            # print(f"URI Value: {uri_value}")
            if uri_value:
                content_uri_lst.append(uri_value)

        # 2-1. uri Matcher를 사용해서 addURI로 추가하는 경우 예를 들면, uriMatcher.addURI("com.example.app.provider", "table1", 1); 이때 "com.example.app.provider/table1"가 content URI가 됨
        matcher = self.uriMatcher_pattern.search(sus_content)
        if matcher:
            arg1 = matcher.group(1).strip()
            arg2 = matcher.group(2).strip()

            # 따옴표로 감싸져 있지 않으면 변수로 판단하여 값 할당 추적
            # 2-2. uri Matcher에 첫번째, 두번째 인자로 들어가는 값이 변수로 저장되어 있는 경우 두개의 변수를 추출하고, 이 변수에 할당되는 값들을 다시 추출
            if not arg1.startswith(("'", '"')):
                arg1 = self.find_variable_value(arg1, sus_content)
            if not arg2.startswith(("'", '"')):
                arg2 = self.find_variable_value(arg2, sus_content)

            if arg1 and arg2:
                arg1 = arg1.replace('"', "")
                arg2 = arg2.replace('"', "")
                content_uri_lst.append(f"content://{arg1}/{arg2}")

        # 3. 상수 선언된 Content URI 탐지
        constant_matches = self.constant_uri_pattern.findall(sus_content)
        content_uri_lst.extend(constant_matches)

        if content_uri_lst:
            # print(content_uri_lst)
            return content_uri_lst
        return []

    def find_variable_value(self, variable_name, content):
        # 주어진 content에서 변수명에 할당된 값 찾기
        matches = self.variable_assignment_pattern.findall(content)
        for var_name, value in matches:
            if var_name == variable_name:
                return value
        return None


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

    def analyze_activity(self, activity):
        try:
            with open(activity, "r", encoding="utf-8") as file:
                sources = file.read()
                return sources
        except UnicodeDecodeError:
            return False

    def run(self, file_path):
        accessible_file = ["java", "kt"]
        accessible_filename = ["AndroidManifest.xml"]
        results = []  # 결과를 저장할 리스트

        if file_path.endswith(tuple(accessible_filename)):
            # print(file_path)
            content = ExtractContent(file_path).extract_content()
            activity_lst = ContentProviderAnalyzer().exported_activity(content)
            for activity in activity_lst:
                # package = content.split("package=")[1].split('"')[1]
                package = file_path.split(os.sep)[1]
                activity_path = activity.replace(".", os.sep) + ".java"
                base_path = os.getcwd()
                whole_path = os.path.join(
                    base_path, "java_src", package, "sources", activity_path
                )
                if os.path.exists(whole_path):
                    sus_content = self.analyze_activity(whole_path)
                    if sus_content:
                        # content URI를 리턴해야됨
                        content_uri_lst = ContentProviderAnalyzer().extract_contentURI(
                            sus_content
                        )
                        results.extend(content_uri_lst)  # content_uri_lst 추가
                        break  # 매칭된 결과를 찾으면 루프 종료

        if file_path.endswith(tuple(accessible_file)):
            content = ExtractContent(file_path).extract_content()
            sql_injection_lines = self.analyze_file(content)
            results.extend(sql_injection_lines)  # SQL 인젝션 라인 추가

        return results  # 모든 결과 반환


if __name__ == "__main__":
    pass
