import re
class HardCodedAnalyzer:
    def __init__(self):
        self._generate_pattern()

    def _generate_pattern(self):
        self.pattern = re.compile(r'<string\s+name="([^"]*?(api|token|key)[^"]*?)"[^>]*>([\w!@#$%^&*()-]{10,})</string>', re.IGNORECASE)

    def run(self, file_content):
        matches = self.pattern.finditer(file_content)
        results = []
        for match in matches:
            name = match.group(1)
            value = match.group(3)
            if "capital" not in name.lower():
                results.append((name, value))
        return results if results else None
    
if __name__ == "__main__":
    pass