import re
from modules.utils import ExtractContent


class LogAnalyzer:

    def __init__(self):
        self.ignore_patterns = [
            r"^\s*//",
            r"^\s*#",
        ]

    def is_ignored(self, line):
        # 라인이 주석인지 확인
        for pattern in self.ignore_patterns:
            if re.search(pattern, line):
                return True
        return False

    def contains_sensitive_info(self, message):
        sensitive_keywords = [
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
        ]

        message_lower = message.lower()
        for keyword in sensitive_keywords:
            if keyword.lower() in message_lower:
                return True
        return False

    def extract_messages(self, content):
        results = []
        log_levels = ["v", "d", "i", "e", "w", "wtf"]

        lines = content.split("\n")

        for level in log_levels:
            pattern = f'Log\\.{level.upper()}\\("'

            for line_num, line in enumerate(lines, start=1):
                if not self.is_ignored(line):
                    if re.search(pattern, line, re.IGNORECASE):
                        if self.contains_sensitive_info(line):
                            results.append((line_num, line))

        return results

    def run(self, file_path):
        accessible_file_types = ["java", "kt"]
        if not file_path.endswith(tuple(accessible_file_types)):
            # print(f"LogAnalyzer: {file_path} is not a java or kotlin file")
            return
        else:
            content = ExtractContent(file_path).extract_content()
        result = self.extract_messages(content)
        return result
