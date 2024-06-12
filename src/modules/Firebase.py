import re

class FirebaseDatabaseAnalyzer:
    def __init__(self):
        self.pattern = re.compile(r'<string name="firebase_database_url">https://[a-zA-Z0-9.-]+\.firebaseio\.com</string>')

    def run(self, file_content):
        matches = self.pattern.findall(file_content)
        return matches if matches else None

if __name__ == "__main__":
    pass
