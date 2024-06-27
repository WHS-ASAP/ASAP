import os
import subprocess
import platform
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

class ApkProcessor:
    def __init__(self, apk_dir='apk_dir', java_dir='java_src', smali_dir='smali_src'):
        self.apk_dir = apk_dir
        self.java_dir = java_dir
        self.smali_dir = smali_dir

        # Set the path according to the system
        if platform.system() == 'Windows':
            self.jadx_path = os.path.join('tools', 'jadx', 'bin', 'jadx.bat')
            self.apktool_path = os.path.join('tools', 'apktool', 'apktool.bat')
        else:
            self.jadx_path = os.path.join('tools', 'jadx', 'bin', 'jadx')
            self.apktool_path = os.path.join('tools', 'apktool', 'apktool_2.9.3.jar')

        if not os.path.exists(self.java_dir):
            os.makedirs(self.java_dir)
        if not os.path.exists(self.smali_dir):
            os.makedirs(self.smali_dir)

    def decompile_apk(self, apk_path):
        apk_name = os.path.basename(apk_path).replace('.apk', '')
        java_output_dir = os.path.join(self.java_dir, apk_name)
        smali_output_dir = os.path.join(self.smali_dir, apk_name)

        if os.path.exists(java_output_dir):
            print(f"{java_output_dir} already exists, skipping decompilation.")
        else:
            os.makedirs(java_output_dir)
            print(f"Decompiling {apk_name} using jadx...")
            try:
                subprocess.run([self.jadx_path, '-d', java_output_dir, apk_path], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error during decompiling {apk_name} with jadx: {e}")
            except Exception as e:
                print(f"Unexpected error during decompiling {apk_name} with jadx: {e}")

        if os.path.exists(smali_output_dir):
            print(f"{smali_output_dir} already exists, skipping smali extraction.")
        else:
            os.makedirs(smali_output_dir)
            print(f"Extracting smali code for {apk_name} using apktool...")
            try:
                if platform.system() == 'Windows':
                     subprocess.run([self.apktool_path, 'd', apk_path, '-o', smali_output_dir, '-f'], check=True)
                else:
                    subprocess.run(['java', '-jar', self.apktool_path, 'd', apk_path, '-o', smali_output_dir, '-f'], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error during extracting smali code for {apk_name} with apktool: {e}")
            except Exception as e:
                print(f"Unexpected error during extracting smali code for {apk_name} with apktool: {e}")

        return java_output_dir, smali_output_dir

    def run(self):
        if not os.path.exists(self.apk_dir):
            print(f"Error: APK directory '{self.apk_dir}' not found.")
            return

        apk_files = [f for f in os.listdir(self.apk_dir) if f.endswith('.apk')]

        for apk_file in apk_files:
            apk_path = os.path.join(self.apk_dir, apk_file)
            java_output_dir, smali_output_dir = self.decompile_apk(apk_path)
            print(f"Java source code for {apk_file} is in {java_output_dir}")
            print(f"Smali code for {apk_file} is in {smali_output_dir}")

if __name__ == "__main__":
    processor = ApkProcessor()
    processor.run()
