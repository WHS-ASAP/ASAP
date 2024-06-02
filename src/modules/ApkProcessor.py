import os
import subprocess
import platform

class ApkProcessor:
    def __init__(self, apk_dir='apk_dir', java_dir='java_src'):
        self.apk_dir = apk_dir
        self.java_dir = java_dir

        # Set the path according to the system
        if platform.system() == 'Windows':
            self.jadx_path = os.path.join('src', 'tools', 'jadx', 'bin', 'jadx.bat')
        else:
            self.jadx_path = os.path.join('src', 'tools', 'jadx', 'bin', 'jadx')

        if not os.path.exists(self.java_dir):
            os.makedirs(self.java_dir)

    def decompile_apk(self, apk_path):
        apk_name = os.path.basename(apk_path).replace('.apk', '')
        java_output_dir = os.path.join(self.java_dir, apk_name)
        
        if not os.path.exists(java_output_dir):
            os.makedirs(java_output_dir)
        
        print(f"Decompiling {apk_name} using jadx...")
        try:
            subprocess.run([self.jadx_path, '-d', java_output_dir, apk_path], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error during decompiling {apk_name}: {e}")
        except Exception as e:
            print(f"Unexpected error during decompiling {apk_name}: {e}")
        return java_output_dir

    def run(self):
        if not os.path.exists(self.apk_dir):
            print(f"Error: APK directory '{self.apk_dir}' not found.")
            return

        apk_files = [f for f in os.listdir(self.apk_dir) if f.endswith('.apk')]
        
        for apk_file in apk_files:
            apk_path = os.path.join(self.apk_dir, apk_file)
            java_output_dir = self.decompile_apk(apk_path)
            print(f"Java source code for {apk_file} is in {java_output_dir}")

if __name__ == "__main__":
    processor = ApkProcessor()
    processor.run()