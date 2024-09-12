import os
import time
import multiprocessing
from modules.DeepLink import DeepLinkAnalyzer
from modules.WebView import WebViewAnalyzer
from modules.Hardcoded import HardCodedAnalyzer
from modules.SQL_Injection import SQLInjectionAnalyzer
from modules.Crypto import CryptoAnalyzer
from modules.LogE import LogAnalyzer
from ASAP_Web import create_app
from ASAP_Web.database import db, save_finding_to_db, Result

app = create_app()

# make dictionary Analyzer - vuln_type
vuln_types = {
    "SQLInjectionAnalyzer": "SQL_Injection",
    "LogAnalyzer": "LogE",
    "HardCodedAnalyzer": "Hardcoded",
    "DeepLinkAnalyzer": "DeepLink",
    "WebViewAnalyzer": "WebView",
    "CryptoAnalyzer": "Crypto",
}

# 기준: 결과값과 취약점까지의 거리/해커원 cvss 기준 / 해커원에서 관련 사례들의 risk책정값
risk_levels = {
    "LogAnalyzer": "High",
    "HardCodedAnalyzer": "High",
    "SQLInjectionAnalyzer": "Medium",
    "DeepLinkAnalyzer": "Medium",
    "WebViewAnalyzer": "Medium",
    "CryptoAnalyzer": "Medium",
}


class Analyzer:
    def __init__(self, java_dir="java_src", smali_dir="smali_src"):
        self.java_dir = java_dir
        self.smali_dir = smali_dir

        self.analyzers = [
            SQLInjectionAnalyzer(),
            CryptoAnalyzer(),
            LogAnalyzer(),
            WebViewAnalyzer(),
            HardCodedAnalyzer(),
            DeepLinkAnalyzer(),
        ]

    def analyze_file(self, file_path, analyzer, now_time, package_name=None):
        result = analyzer.run(file_path)

        if result:
            with app.app_context():
                save_finding_to_db(
                    package_name,
                    file_path,
                    vuln_types[analyzer.__class__.__name__],
                    risk_levels[analyzer.__class__.__name__],
                    str(result),
                    now_time,
                )

    def process_directory(self, directory, analyzers, now_time, target_files=None):
        tasks = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                for analyzer in analyzers:
                    # 각 파일 분석 작업을 멀티프로세싱으로 처리
                    tasks.append((file_path, analyzer, now_time, directory))

        # 멀티프로세싱으로 작업 수행
        with multiprocessing.Pool() as pool:
            pool.starmap(self.analyze_file, tasks)

    def process_root_directory(
        self,
        root_directory,
        analyzers,
        now_time,
        package_names_to_skip,
        target_files=None,
    ):
        for package_name in os.listdir(root_directory):
            print(package_name)
            package_path = os.path.join(root_directory, package_name)
            package_name = (
                package_path.replace(root_directory, "").strip(os.sep).split(os.sep)[0]
            )
            time.sleep(0.2)
            if package_name not in package_names_to_skip:
                self.process_directory(package_path, analyzers, now_time, target_files)
            else:
                print(f"Skipping already analyzed package: {package_name}")

    def run(self):
        if not os.path.exists(self.java_dir):
            print(f"Error: Source directory '{self.java_dir}' not found.")
            return

        with app.app_context():
            db.create_all()

        now_time = time.strftime("%B %d %Y")

        package_names_to_skip = self.get_analyzed_package_names()
        print("already analyzed package: ", package_names_to_skip)

        self.process_root_directory(
            self.java_dir, self.analyzers, now_time, package_names_to_skip
        )

    def get_analyzed_package_names(self):
        with app.app_context():
            package_names = {
                result.package_name
                for result in Result.query.with_entities(Result.package_name).distinct()
            }
            # 경로에서 'java_src/' 부분을 제거하고 패키지 이름만 추출
            cleaned_package_names = {
                os.path.relpath(name, "java_src") for name in package_names
            }
            return cleaned_package_names


if __name__ == "__main__":
    start_time = time.time()
    analyzer = Analyzer()
    analyzer.run()
    print(f"Execution time: {time.time() - start_time:.2f} seconds")
