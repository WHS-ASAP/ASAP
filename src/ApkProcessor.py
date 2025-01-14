import os, time
import subprocess
import platform
import sys
from typing import Optional  # Optional import 추가

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))


class ApkProcessor:
    def __init__(self, apk_dir: str = "apk_dir", java_dir: str = "java_src"):
        self.apk_dir = apk_dir
        self.java_dir = java_dir
        self.setup_tools()

    def setup_tools(self):
        """Set up paths for decompilation tools"""
        print("\033[94m[*] Initializing APK processor...\033[0m")

        self.apktool_path = os.path.join("tools", "apktool", "apktool_2.9.3.jar")
        self.jadx_path = os.path.join(
            "tools",
            "jadx",
            "bin",
            "jadx.bat" if platform.system() == "Windows" else "jadx",
        )

        if not os.path.exists(self.java_dir):
            os.makedirs(self.java_dir)
            print("\033[92m[+] Created output directory\033[0m")

    def decompile_apk(self, apk_path: str) -> Optional[str]:
        """Decompile APK file using jadx"""
        apk_name = os.path.basename(apk_path).replace(".apk", "")
        java_output_dir = os.path.join(self.java_dir, apk_name)

        if os.path.exists(java_output_dir):
            print(f"\033[93m[!] {apk_name} already decompiled, skipping...\033[0m")
            return java_output_dir

        print(f"\033[94m[*] Decompiling {apk_name} using jadx...\033[0m")
        os.makedirs(java_output_dir)

        try:
            subprocess.run(
                [self.jadx_path, "-d", java_output_dir, apk_path], check=True
            )
            print(f"\033[92m[+] Successfully decompiled {apk_name}\033[0m")
            return java_output_dir
        except subprocess.CalledProcessError as e:
            print(f"\033[91m[!] Error decompiling {apk_name}: {e}\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Unexpected error: {e}\033[0m")
        return None

    def run(self):
        """Process all APK files in the directory"""
        if not os.path.exists(self.apk_dir):
            print(f"\033[91m[!] Error: APK directory '{self.apk_dir}' not found\033[0m")
            return

        apk_files = [f for f in os.listdir(self.apk_dir) if f.endswith(".apk")]
        print(f"\033[94m[*] Found {len(apk_files)} APK files to process\033[0m")

        for apk_file in apk_files:
            apk_path = os.path.join(self.apk_dir, apk_file)
            output_dir = self.decompile_apk(apk_path)
            if output_dir:
                print(f"\033[92m[+] Output directory: {output_dir}\033[0m")
