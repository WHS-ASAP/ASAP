import re

class CryptoAnalyzer:
    def __init__(self):
        # 암호화 관련 키워드 패턴 목록
        self.crypto_patterns = [
            # 취약한 PRNG 관련
            r'\bjava\.util\.Random\b',
            r'\bMath\.random\b',
            r'\bnew Random\b',
            r'\bnew java\.util\.Random\b',

            # 취약한 암호화 알고리즘 관련
            r'\bCipher\.getInstance\("DES(/[A-Z]+)?(/[A-Z0-9]+)?"\)\b',
            r'\bCipher\.getInstance\(".*ECB(/[A-Z]+)?(/[A-Z0-9]+)?"\)\b',
            r'\bMessageDigest\.getInstance\("MD5"\)\b',
            r'\bMessageDigest\.getInstance\("SHA[-_]?1"\)\b',
            r'\bCipher\.getInstance\("RC4(/[A-Z]+)?(/[A-Z0-9]+)?"\)\b',
            r'\bSecretKeyFactory\.getInstance\("PBKDF1"\)\b',
            r'\bCipher\.getInstance\("TripleDES(/[A-Z]+)?(/[A-Z0-9]+)?"\)\b',
            r'\bCipher\.getInstance\("3DES(/[A-Z]+)?(/[A-Z0-9]+)?"\)\b',

            # 하드코딩된 키 또는 초기화 벡터 관련
            r'\bnew SecretKeySpec\b',
            r'\bkeyBytes =\b',
            r'\bivBytes =\b',
            r'\bkey = "\b',
            r'\biv = "\b'
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
                        findings.append((line_num, line))
        return findings