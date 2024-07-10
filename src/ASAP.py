import os
from Analyzer import Analyzer
from apk_Downloader import ApkDownloader
from ApkProcessor import ApkProcessor
import asyncio

async def main():

    # 1. apk decompile
    processor = ApkProcessor()
    processor.run()

    # 2. Analyze
    analyzer = Analyzer()
    analyzer.run()

if __name__ == "__main__":
    asyncio.run(main())