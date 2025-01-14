# ASAP.py
import asyncio
import argparse
import sys
from Analyzer import Analyzer
from ApkProcessor import ApkProcessor
from ApkDownloader import ApkDownloader


class ASAPCLI:
    def __init__(self):
        self.parser = self.create_parser()

    @staticmethod
    def print_banner():
        banner = """
        \033[92m
         █████╗ ███████╗ █████╗ ██████╗ 
        ██╔══██╗██╔════╝██╔══██╗██╔══██╗
        ███████║███████╗███████║██████╔╝
        ██╔══██║╚════██║██╔══██║██╔═══╝ 
        ██║  ██║███████║██║  ██║██║     
        ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     
        \033[0m
        \033[93m[ 🔍 Android Static Analysis Platform v1.0 🎯 ]\033[0m
        \033[96m[ 🛡️  Automated Security Analysis Tool for Android Apps 🔒 ]\033[0m
        
        \033[90m[ Features:
        🔹 APK Download (-dn)  🔹 Decompile (-dc)  🔹 Analysis (-a) ]\033[0m
        
        \033[95m[ 🚀 Ready to Download & Analyze Android Applications 📱 ]\033[0m
        """
        print(banner)

    @staticmethod
    def print_usage():
        usage = """
        \033[95m🔧 Command Line Usage:\033[0m
            python3 ASAP.py              # Run full pipeline (download + decompile + analyze)
            python3 ASAP.py -dn          # Download APKs only
            python3 ASAP.py -dc          # Decompile only
            python3 ASAP.py -a           # Analyze only
            python3 ASAP.py -dc -a       # Decompile and analyze
            python3 ASAP.py -dn -dc      # Download and decompile
            
        \033[95m⚙️  Options:\033[0m
            -dn, --download    ⬇️  Download APKs from target.txt
            -dc, --decompile   📤 Decompile APK files
            -a,  --analyze     🔍 Analyze decompiled files
            -h,  --help        ℹ️  Show this help message
            
        \033[93m🔔 Note: Default behavior (no options) runs the complete pipeline\033[0m
        """
        print(usage)

    def create_parser(self):
        parser = argparse.ArgumentParser(
            description="ASAP: Android Static Analysis Platform"
        )
        parser.add_argument(
            "-dn",
            "--download",
            action="store_true",
            help="Download APKs from target.txt",
        )
        parser.add_argument(
            "-dc", "--decompile", action="store_true", help="Decompile APK files"
        )
        parser.add_argument(
            "-a", "--analyze", action="store_true", help="Analyze decompiled files"
        )
        return parser

    async def run(self):
        try:
            args = self.parser.parse_args()

            # If no arguments provided, run full pipeline
            if not any([args.download, args.decompile, args.analyze]):
                print(
                    "\033[94m[*] Running complete pipeline (download + decompile + analyze)\033[0m"
                )
                await self.run_download()
                self.run_decompile()
                self.run_analyze()
                return

            # Run selected steps
            if args.download:
                await self.run_download()

            if args.decompile:
                self.run_decompile()

            if args.analyze:
                self.run_analyze()

        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)}\033[0m")
            sys.exit(1)

    async def run_download(self):
        """Run APK download step"""
        print("\n\033[94m[*] Starting APK download...\033[0m")
        downloader = ApkDownloader("docs/target.txt")
        await downloader.run()

    def run_decompile(self):
        """Run decompilation step"""
        print("\n\033[94m[*] Starting APK decompilation...\033[0m")
        processor = ApkProcessor()
        processor.run()

    def run_analyze(self):
        """Run analysis step"""
        print("\n\033[94m[*] Starting analysis...\033[0m")
        analyzer = Analyzer()
        analyzer.run()


async def main():
    cli = ASAPCLI()
    cli.print_banner()

    if len(sys.argv) == 2 and sys.argv[1] in ["-h", "--help"]:
        cli.print_usage()
        return

    await cli.run()


if __name__ == "__main__":
    asyncio.run(main())
