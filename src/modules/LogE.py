import re

class LogAnalyzer:
    
    def __init__(self):
        self.ignore_patterns = [
            r'^\s*//',
            r'^\s*\*',
            r'^\s*#', 
            r'^\s*/\*',
            r'\*/\s*$',
            r'".*"',
            r"'.*'" 
        ]
        
        
    def is_ignored(self, line):
        # 라인이 주석이나 문자열인지 확인
        for pattern in self.ignore_patterns:
            if re.search(pattern, line):
                return True
        return False
        
    def contains_sensitive_info(self, message):
        sensitive_keywords = [
            'access_token', 'password', 'secret', 'api_key', 'session_id',
            'private_key', 'auth_token', 'credit_card', 'ssn', 'pin_code'
        ]
        
        message_lower = message.lower()
        for keyword in sensitive_keywords:
            if keyword in message_lower:
                return True
        return False
    
    def extract_messages(self, content):
        results = []
        log_levels = ['v', 'd', 'i', 'e', 'wtf']
        
        lines = content.split('\n')
        
        for level in log_levels:
            pattern = f'Log.{level}("'

            for line_num, line in enumerate(lines, start=1):
                if not self.is_ignored(line):
                    if pattern in line:
                        if self.contains_sensitive_info(line):
                            print("!!!!!")
                            results.append((f"Line {line_num}: {line.strip()}"))
                
        return results
    
    
    def run(self, content):
        result = self.extract_messages(content)
        return result
