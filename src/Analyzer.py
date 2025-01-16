import os
import time
from typing import List, Dict, Any, Set
from modules.DeepLink import DeepLinkAnalyzer
from modules.WebView import WebViewAnalyzer
from modules.Hardcoded import HardCodedAnalyzer
from modules.SQL_Injection import SQLInjectionAnalyzer
from modules.Permission import PermissionAnalyzer
from modules.Crypto import CryptoAnalyzer
from modules.LogE import LogAnalyzer
from modules.utils import FilePathCheck
from ASAP_Web import create_app
from ASAP_Web.database import db, save_finding_to_db, Result


class Analyzer:
    def __init__(self, java_dir: str = "java_src", smali_dir: str = "smali_src"):
        self.java_dir = java_dir
        self.smali_dir = smali_dir
        self.setup_analyzers()
        self.app = create_app()

    def setup_analyzers(self):
        """Initialize analyzers with color-coded categories"""
        print("\033[94m[*] Setting up analyzers...\033[0m")

        self.analyzers = {
            "java": [
                (SQLInjectionAnalyzer(), [".java"]),
                (CryptoAnalyzer(), [".java"]),
                (LogAnalyzer(), [".java"]),
            ],
            "xml": [
                (PermissionAnalyzer(), [".xml"]),
                (WebViewAnalyzer(), [".xml"]),
                (HardCodedAnalyzer(), [".xml", ".java"]),
            ],
            "smali": [(DeepLinkAnalyzer(), [".smali", ".xml"])],
        }

        self.risk_levels = {
            "SQLInjectionAnalyzer": "\033[91mHigh\033[0m",
            "LogAnalyzer": "\033[91mHigh\033[0m",
            "HardCodedAnalyzer": "\033[91mHigh\033[0m",
            "DeepLinkAnalyzer": "\033[93mMedium\033[0m",
            "WebViewAnalyzer": "\033[93mMedium\033[0m",
            "CryptoAnalyzer": "\033[93mMedium\033[0m",
            "PermissionAnalyzer": "\033[92mLow\033[0m",
        }

    def analyze_file(
        self,
        file_path: str,
        analyzers: List,
        now_time: str,
        smali_dir: str = None,
        package_name: str = None,
    ) -> List:
        """Analyze a single file with multiple analyzers"""
        print(f"\033[94m[*] Analyzing {os.path.basename(file_path)}...\033[0m")

        findings = []
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()

            for analyzer, extensions in analyzers:
                if any(file_path.endswith(ext) for ext in extensions):
                    result = self._run_analyzer(analyzer, content, file_path, smali_dir)

                    if result:
                        findings.append(
                            (file_path, analyzer.__class__.__name__, result)
                        )
                        self._save_finding(
                            package_name, file_path, analyzer, result, now_time
                        )

        return findings

    def run(self):
        """Run all analyzers on the codebase"""
        if not os.path.exists(self.java_dir) or not os.path.exists(self.smali_dir):
            print(f"\033[91m[!] Error: Source directories not found\033[0m")
            return

        print("\033[94m[*] Starting analysis...\033[0m")
        start_time = time.time()

        with self.app.app_context():
            db.create_all()
            analyzed_packages = self.get_analyzed_package_names()

            self._process_all_directories(analyzed_packages)

        duration = time.time() - start_time
        print(f"\033[92m[+] Analysis completed in {duration:.2f} seconds\033[0m")

    def _process_all_directories(self, skip_packages: Set[str]):
        """Process all directories with appropriate analyzers"""
        now_time = time.strftime("%B %d %Y")

        for analyzer_type, config in [
            ("java", (self.analyzers["java"], None)),
            ("xml", (self.analyzers["xml"], ["AndroidManifest.xml", "strings.xml"])),
            ("smali", (self.analyzers["smali"], ["AndroidManifest.xml"])),
        ]:
            analyzers, target_files = config
            source_dir = self.smali_dir if analyzer_type == "smali" else self.java_dir

            print(f"\033[94m[*] Running {analyzer_type} analysis...\033[0m")
            self.process_root_directory(
                source_dir, analyzers, now_time, skip_packages, target_files
            )
