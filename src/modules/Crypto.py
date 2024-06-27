import re

class CryptoAnalyzer:
    def __init__(self):
        # 암호화 관련 키워드 패턴 목록
        self.crypto_patterns = [
            r'\bCipher\b',
            r'\bMessageDigest\b',
            r'\bSecretKeySpec\b',
            r'\bKeyGenerator\b',
            r'\bMac\b',
            r'\bKeyPairGenerator\b',
            r'\bSignature\b',
            r'\bCipherInputStream\b',
            r'\bCipherOutputStream\b',
            r'\bCipher.getInstance\b',
            r'\bKeyStore\b',
            r'\bSecureRandom\b',
            r'\bKeyAgreement\b'
        ]
        
        # 주석이나 문자열 내의 키워드 무시하기 위한 패턴
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

    def run(self, content):
        findings = []
        lines = content.split('\n')
        for line_num, line in enumerate(lines, start=1):
            if not self.is_ignored(line):
                for pattern in self.crypto_patterns:
                    if re.search(pattern, line):
                        findings.append(f"Line {line_num}: {line.strip()}")
        return findings