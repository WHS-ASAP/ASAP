# ApkDownloader.py
import asyncio
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
import os
import urllib.request
from tqdm import tqdm
import ssl


class ApkDownloader:
    def __init__(self, target_file="docs/target.txt"):
        self.target_file = target_file
        self.ssl_context = ssl._create_unverified_context()
        self.max_retries = 3
        self.timeout = 60000
        self.delay = 5

    async def download_apk(self, url, package_name):
        """APK 파일 다운로드 함수"""
        if not os.path.exists("apk_dir"):
            os.makedirs("apk_dir")
            print("📁 Created download directory: apk_dir")

        file_path = os.path.join("apk_dir", f"{package_name}.apk")

        if os.path.exists(file_path):
            print(f"ℹ️  {package_name}.apk already exists. Skipping...")
            return True

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, context=self.ssl_context) as response:
                total_size = int(response.headers.get("Content-Length", 0))

                with open(file_path, "wb") as f, tqdm(
                    desc=f"⬇️ Downloading {package_name}.apk",
                    total=total_size,
                    unit="iB",
                    unit_scale=True,
                    unit_divisor=1024,
                ) as progress_bar:
                    while True:
                        chunk = response.read(8192)
                        if not chunk:
                            break
                        size = f.write(chunk)
                        progress_bar.update(size)

            print(f"✅ Download completed: {file_path}")
            return True
        except Exception as e:
            print(f"❌ Download error: {str(e)}")
            if os.path.exists(file_path):
                os.remove(file_path)
            return False

    async def search_and_download_apk(self, package_name):
        """Function to search and download APK with retry mechanism"""
        for attempt in range(self.max_retries):
            if attempt > 0:
                print(f"🔄 Retry attempt {attempt + 1}/{self.max_retries}...")
                await asyncio.sleep(self.delay)

            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-dev-shm-usage",
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-gpu",
                        "--disable-web-security",
                        "--disable-features=IsolateOrigins,site-per-process",
                    ],
                )
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    viewport={"width": 1280, "height": 800},
                    accept_downloads=True,
                )

                page = await context.new_page()
                page.set_default_timeout(self.timeout)

                try:
                    print(f"\n📱 Processing package: {package_name}")
                    try:
                        await page.goto(
                            "https://apkcombo.com",
                            wait_until="domcontentloaded",
                            timeout=self.timeout,
                        )
                        await page.wait_for_load_state("networkidle", timeout=30000)
                    except Exception as e:
                        if "Timeout" not in str(e):
                            raise e

                    print(f"🔎 Searching '{package_name}'...")
                    search_input = await page.wait_for_selector(
                        'input.ainput.awesomplete[name="q"]'
                    )
                    await search_input.fill(package_name)

                    search_button = await page.wait_for_selector(
                        "button.button.button-search.is-link"
                    )
                    await search_button.click()

                    try:
                        await page.wait_for_load_state("networkidle", timeout=30000)
                    except:
                        pass

                    print("🔍 Looking for app link in search results...")
                    content = await page.content()
                    soup = BeautifulSoup(content, "html.parser")

                    app_link = soup.find("a", class_="button is-success is-fullwidth")

                    if app_link and "href" in app_link.attrs:
                        app_url = f"https://apkcombo.com{app_link['href']}"
                        print(f"✅ Found app page: {app_url}")

                        try:
                            await page.goto(
                                app_url,
                                wait_until="domcontentloaded",
                                timeout=self.timeout,
                            )
                            await page.wait_for_load_state("networkidle", timeout=30000)
                        except Exception as e:
                            if "Timeout" not in str(e):
                                raise e

                        print("🔍 Searching for APK file...")
                        content = await page.content()
                        soup = BeautifulSoup(content, "html.parser")

                        file_list = soup.find("ul", class_="file-list")
                        if file_list:
                            apk_link = None
                            for link in file_list.find_all("a", class_="variant octs"):
                                if (
                                    "href" in link.attrs
                                    and not "XAPK" in link.get_text()
                                ):
                                    apk_link = link["href"]
                                    break

                            if apk_link:
                                print(f"✅ Found APK download link")
                                await browser.close()
                                return await self.download_apk(apk_link, package_name)
                            else:
                                print("⚠️ No APK file found (might be XAPK only)")
                                await browser.close()
                                return False
                        else:
                            print("❌ File list not found")
                            await browser.close()
                            return False
                    else:
                        print("❌ App link not found")
                        await browser.close()
                        return False

                except Exception as e:
                    print(f"❌ Error occurred: {str(e)}")
                    await browser.close()
                    if attempt == self.max_retries - 1:
                        return False
                    continue

        return False

    async def run(self):
        """Process package list from target.txt"""
        if not os.path.exists(self.target_file):
            print(f"❌ target.txt not found: {self.target_file}")
            return

        try:
            with open(self.target_file, "r") as f:
                packages = [line.strip() for line in f.readlines() if line.strip()]

            if not packages:
                print("⚠️ target.txt is empty.")
                return

            print(f"📋 Processing {len(packages)} app packages.")

            for i, package in enumerate(packages):
                if i > 0:
                    await asyncio.sleep(self.delay)

                success = await self.search_and_download_apk(package)
                if not success:
                    print(f"⚠️ {package} might need manual download.")
                print("-" * 50)

            print("\n✅ All packages processed")

        except Exception as e:
            print(f"❌ Error processing target.txt: {str(e)}")


async def main():
    print("----------------------------------------")
    print("APKCombo Downloader")
    print("Target file: docs/target.txt")
    print("Download directory: apk_dir")
    print("----------------------------------------")

    downloader = ApkDownloader()
    await downloader.run()


if __name__ == "__main__":
    asyncio.run(main())
