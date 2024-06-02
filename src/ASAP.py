import os
from modules.Analyzer import Analyzer
from modules.apk_Downloader import ApkDownloader
from modules.ApkProcessor import ApkProcessor
import asyncio

async def main():
    apk_downloader = ApkDownloader()
    await apk_downloader.run()
    # Check if apk_dir exists after downloading
    if not os.path.exists('apk_dir') or not any(f.endswith('.apk') for f in os.listdir('apk_dir')):
        print("Error: APK directory 'apk_dir' not found or no APK files downloaded. Exiting.")
        return
    # 2. apk decompile
    processor = ApkProcessor()
    processor.run()

    # 3. Analyze
    analyzer = Analyzer()
    analyzer.run()

if __name__ == "__main__":
    asyncio.run(main())



