import os
import sys
from hardcoding_pattern import ApiKeyAnalyzer, FirebaseDatabaseAnalyzer

class Analyzer:
    def __init__(self, java_dir='java_src'):
        self.java_dir = java_dir
        
        self.analyzers = [ApiKeyAnalyzer(),FirebaseDatabaseAnalyzer()]

    def analyze_file(self, file_path):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
            findings = []
            for analyzer in self.analyzers:
                result = analyzer.run(content)
                if result:
                    findings.append((file_path, result))
            return findings

    def run(self):
        if not os.path.exists(self.java_dir):
            print(f"Error: Java source directory '{self.java_dir}' not found.")
            return

# 여기서도 발견했을 때 출력되는 부분에 대해서 수정 필요,, 각 pattern 안에서 출력하도록 할지 아니면 그냥 이렇게 갈지 고민중
        for root, dirs, files in os.walk(self.java_dir):
            for file in files:
                if file.endswith(".java") or file.endswith(".xml"):
                    # print(f"Analyzing {file}...")
                    file_path = os.path.join(root, file)
                    findings = self.analyze_file(file_path)
                    if findings:
                        for finding in findings:
                            print(f"Potential issue found in {finding[0]}: {finding[1]}")

if __name__ == "__main__":
    analyzer = Analyzer()
    analyzer.run()
