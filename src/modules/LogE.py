import re
from difflib import SequenceMatcher
from modules.utils import ExtractContent


class LogAnalyzer:

    def __init__(self):
        self.ignore_patterns = [
            r"^\s*//",  # 주석일 경우
            r"^\s*#",
        ]
        # 민감한 정보를 탐지하기 위한 키워드 목록, 향후 추가 혹은 수정 필요
        self.sensitive_keywords = [
            "access_token",
            "password",
            "secret",
            "admin_id",
            "adminId",
            "admin_pw",
            "adminPw",
            "admin_password",
            "admin_secret",
            "api_secret",
            "user_id",
            "userId",
            "user_pw",
            "userPw",
            "user_password",
            "user_secret",
            "api_key",
            "private_key",
            "privateKey",
            "private_token",
            "privateToken",
            "auth_token",
            "authToken",
            "credit_card",
            "ssn",
            "pin_code",
            "session_id",
            "IP_address",
            "IPaddress",
            "Cookies",
            "Cookie",
            "SESSIONID",
            "oAuthToken",
            "getAccessToken()",
            "pin",
            "pwd",
            "passwd",
        ]
        # 무시할 예외 토큰 키워드 목록, 향후 추가 혹은 수정 필요
        self.excluded_keywords = ["firebase", "FIS auth token", "firebaseInstanceId"]
        self.allowed_log_prefix = (
            "Log"  # 표준 로그 형식만 탐지, 커스텀 로그 형식 무시하기 위핵서 설정
        )

        # 상용 라이브러리 경로 목록 (무시할 경로), 향후 추가 혹은 수정 필요
        self.excluded_paths = [
            "com/google/firebase",  # Firebase 관련 상용 경로
            "com/google/android",  # Google Android 관련 상용 경로
        ]

    # 주석인지 확인하는 메서드
    def is_ignored(self, line):
        # 주석 패턴과 일치하는지 확인하여 주석이면 True 반환
        for pattern in self.ignore_patterns:
            if re.search(pattern, line):
                return True
        return False

    # 두 문자열이 비슷한지(80% 이상 유사) 확인하는 메서드
    def is_similar(self, a, b):
        # 두 문자열이 80% 이상 유사하면 True 반환, 이 부분도 tuning이 필요할 수 있음
        return SequenceMatcher(None, a.lower(), b.lower()).ratio() > 0.8

    # 로그 메시지에 민감한 정보가 포함되어 있는지 확인하는 메서드
    def contains_sensitive_info(self, message):
        # 민감한 정보를 포함하고 있는지 확인. 예외적인 키워드는 무시
        message_lower = message.lower()

        # 예외적인 민감 정보는 탐지 대상에서 제외
        for excluded in self.excluded_keywords:
            if excluded.lower() in message_lower:
                return False

        # 민감한 키워드가 포함되어 있는지 확인
        for keyword in self.sensitive_keywords:
            if keyword.lower() in message_lower:
                return True
            # 유사한 키워드가 있는지 확인 (ex: 오타가 있는 경우, password -> pwd 같이 줄여서 사용하는 경우 등)
            if any(
                self.is_similar(keyword, word)
                for word in re.findall(r"\w+", message_lower)
            ):
                return True
        return False

    # 로그 주변 코드를 분석하여 민감한 정보가 포함되어 있는지 확인하는 메서드, 이 부분은 tuning이 많이 필요하다고 생각됨..
    def analyze_context(self, content, line_num):
        # 로그 주변의 코드를 분석하여 민감한 정보와 연관된 맥락인지 확인
        lines = content.split("\n")
        surrounding_code = "\n".join(lines[max(0, line_num - 10) : line_num + 10])
        # 민감한 정보와 연관된 키워드 목록, 향후 추가 혹은 수정 필요

        for keyword in self.sensitive_keywords:
            if keyword in surrounding_code:
                return True
        return False

    # 파일 경로가 상용 라이브러리 경로에 해당하는지 확인하는 메서드
    def should_exclude_file(self, file_path):
        # 파일 경로가 상용 라이브러리 경로에 포함되면 True 반환
        for excluded_path in self.excluded_paths:
            if excluded_path in file_path:
                return True
        return False

    # 로그 메시지에서 민감한 정보를 탐지하여 반환하는 메서드
    def extract_messages(self, content):
        # 로그 메시지를 분석하여 민감한 정보가 포함된 라인을 반환
        results = []
        log_levels = ["v", "d", "i", "e", "w", "wtf"]

        lines = content.split("\n")

        for level in log_levels:
            # 각 로그 레벨 패턴 생성
            pattern = f'{self.allowed_log_prefix}\\.{level.upper()}\\("'

            for line_num, line in enumerate(lines, start=1):
                # 주석이 아니고, 로그 형식에 맞는 메시지인지 체크
                if not self.is_ignored(line):
                    if not line.strip().startswith(self.allowed_log_prefix):
                        continue
                    # 로그 레벨에 맞는 로그 메시지인지 체크
                    if re.search(pattern, line, re.IGNORECASE):
                        # 민감한 정보를 포함하거나 맥락적으로 민감한 정보와 연관된 경우 결과에 최종으로 추가
                        if self.contains_sensitive_info(line) or self.analyze_context(
                            content, line_num
                        ):
                            results.append((line_num, line))

        return results

    def run(self, file_path):

        accessible_file_types = ["java", "kt"]

        # 파일 경로가 상용 라이브러리 경로에 해당하면 분석 제외
        if self.should_exclude_file(file_path):
            return

        if not file_path.endswith(tuple(accessible_file_types)):
            return
        else:
            content = ExtractContent(file_path).extract_content()
        result = self.extract_messages(content)
        return result
