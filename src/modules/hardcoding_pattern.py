import re

# From AVASTA -> 이건 연구해서 다시 해볼 필요성 있음
class ApiKeyAnalyzer:
    def __init__(self):
        self.pattern = re.compile(r"['\"]api[_-]?key['\"]\s*:\s*[\"']?[a-zA-Z0-9]+[\"']?")

    def run(self, file_content):
        matches = self.pattern.findall(file_content)
        return matches if matches else None

class PasswordAnalyzer:
    def __init__(self):
        self.pattern = re.compile(r"['\"]password['\"]\s*[\"']?[a-zA-Z0-9]+[\"']?")

    def run(self, file_content):
        matches = self.pattern.findall(file_content)
        return matches if matches else None
# --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
class FirebaseDatabaseAnalyzer:
    def __init__(self):
        self.pattern = re.compile(r'<string name="firebase_database_url">https://[a-zA-Z0-9.-]+\.firebaseio\.com</string>')

    def run(self, file_content):
        matches = self.pattern.findall(file_content)
        return matches if matches else None

if __name__ == "__main__":
    pass
