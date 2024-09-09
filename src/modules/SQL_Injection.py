import re, os
from modules.utils import ExtractContent, ExceptCPkeyword


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
        # print(provider_name)
        return provider_name

    def extract_contentURI(self, sus_content):
        # 전체 추출한 Content URI 리스트
        content_uri_lst = []

        # 1-1. Uri.parse()에서 () 사이의 모든 값을 추출
        uri_parse_matches = self.uriParse_pattern.finditer(sus_content)
        for match in uri_parse_matches:
            uri_value = match.group(1)
            if not uri_value.startswith(
                ("content://")
            ):  # 따옴표로 감싸져 있지 않으면 변수로 판단
                # 변수명을 기반으로 해당 값 할당 추적
                # 1-2. URI = "content://~"와 같이 변수에 저장 후, Uri.parse로 사용하는 경우
                uri_value = self.find_variable_value(uri_value, sus_content)
            # google, facebook, firebase 등 외부 패키지의 URI는 제외

            if uri_value and not ExceptCPkeyword().check(uri_value):
                content_uri_lst.append(uri_value)

        # 2-1. uri Matcher를 사용해서 addURI로 추가하는 경우
        matcher = self.uriMatcher_pattern.search(sus_content)
        if matcher:
            arg1 = matcher.group(1).strip()
            arg2 = matcher.group(2).strip()

            # 따옴표로 감싸져 있지 않으면 변수로 판단하여 값 할당 추적
            if not arg1.startswith(("'", '"')):
                arg1 = self.find_variable_value(arg1, sus_content)
            if not arg2.startswith(("'", '"')):
                arg2 = self.find_variable_value(arg2, sus_content)

            if arg1 and arg2:
                arg1 = arg1.replace('"', "")
                arg2 = arg2.replace('"', "")
                if not ExceptCPkeyword().check(arg1) and not ExceptCPkeyword().check(
                    arg2
                ):
                    content_uri_lst.append(f"content://{arg1}/{arg2}")

        # 3. 상수 선언된 Content URI 탐지
        constant_matches = self.constant_uri_pattern.findall(sus_content)

        # constant_matches가 리스트인 경우, 각 요소에 대해 check 메서드를 호출
        for uri in constant_matches:
            if not ExceptCPkeyword().check(uri):
                content_uri_lst.append(uri)

        if content_uri_lst:
            return content_uri_lst
        return []

    def find_variable_value(self, variable_name, content):
        # 주어진 content에서 변수명에 할당된 값 찾기
        matches = self.variable_assignment_pattern.findall(content)
        for var_name, value in matches:
            if var_name == variable_name:
                return value
        return None


# query문에 대한 SQL Injection 패턴을 찾는 클래스
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
        content_uri_lst = []  # content URI 리스트
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
                        # 이 경우에는 확실한 경우이기 때문에 확실하게 접근가능한 content provider라는 메세지와 함께 content_uri_lst를 반환
                        # 튜플로 묶어서 추가
                        # content_uri_lst의 URI를 문자열로 변환하여 추가
                        if content_uri_lst:
                            results.append(
                                "Surely Accessible Content Provider : "
                                + ", ".join(content_uri_lst)
                            )
                            # results.extend(content_uri_lst)  # content_uri_lst 추가
                            break  # 매칭된 결과를 찾으면 루프 종료

        if file_path.endswith(tuple(accessible_file)):
            content = ExtractContent(file_path).extract_content()
            sql_injection_lines = self.analyze_file(content)
            content_uri_lst_tmp = ContentProviderAnalyzer().extract_contentURI(content)
            results.extend(sql_injection_lines)  # SQL 인젝션 라인 추가
            # content_uri_lst2에서 content_uri_lst에 없는 값만 추가
            content_uri_lst2 = []
            for uri in content_uri_lst_tmp:
                if uri not in content_uri_lst:
                    content_uri_lst2.append(uri)
            if content_uri_lst2:
                results.append(
                    "Possible Accessible Content Provider : "
                    + ", ".join(content_uri_lst2)
                )

        return results  # 모든 결과 반환


if __name__ == "__main__":
    pass
