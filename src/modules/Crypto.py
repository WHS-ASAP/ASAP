import re
from utils import ExtractContent

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
            r'\bivBytes\s*=\s*{[^}]+}',
            r'\biv\s*=\s*"[^\"]+"',
            r'\bivBytes\s*=\s*new\s+byte\[\]\s*{[^}]+}'
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
        for pattern in self.ignore_patterns:
            if re.search(pattern, line):
                return False
        return True

    def run(self, file_path):
        need_file_list = ['shared', 'pref']
        if not any(ext in file_path for ext in need_file_list):
            return
        extractor = ExtractContent(file_path)
        content = extractor.extract_content()
        findings = []
        lines = content.split('\n')
        for line_num, line in enumerate(lines, start=1):
            if self.is_ignored(line):
                for pattern in self.crypto_patterns:
                    if re.search(pattern, line):
                        findings.append((line_num, line))
        return findings