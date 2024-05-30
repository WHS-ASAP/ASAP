import os
import time
from tqdm import tqdm
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import urllib.request

class ApkDownloader:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        }
        self.base_apkpure_url = "https://d.apkpure.com/b/APK/"

    def download_apk(self, package_name):
        download_url = f"{self.base_apkpure_url}{package_name}?version=latest"
        print(download_url)
        max_retries = 3
        retry_delay = 5
        for attempt in range(max_retries):
            try:
                req = urllib.request.Request(download_url, headers=self.headers)
                with urllib.request.urlopen(req) as response:
                    if response.status == 200:
                        if not os.path.exists('apk_dir'):
                            os.makedirs('apk_dir')

                        apk_path = os.path.join('apk_dir', f"{package_name}.apk")

                        if os.path.exists(apk_path):
                            print(f"{package_name} already exists in apk_dir. Skipping download.")
                            return

                        total_size = int(response.getheader('Content-Length', 0))

                        with open(apk_path, 'wb') as file, tqdm(
                            desc=f"Downloading {package_name}",
                            total=total_size,
                            unit='iB',
                            unit_scale=True,
                            unit_divisor=1024,
                        ) as bar:
                            while True:
                                chunk = response.read(1024)
                                if not chunk:
                                    break
                                file.write(chunk)
                                bar.update(len(chunk))

                        print(f"\nDownloaded {package_name} to {apk_path}")
                        break  # Exit the loop if download is successful
                    else:
                        print(f"Failed to download {package_name}. Status code: {response.status}")
            except Exception as e:
                print(f"Error: {e}")
                if attempt < max_retries - 1:
                    print(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    print(f"Exceeded maximum retries. Could not download {package_name}.")

    def search_hackerone(self):
        # Set up Selenium WebDriver
        options = Options()
        options.headless = True
        service = ChromeService(executable_path=ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        driver.get("https://hackerone.com/opportunities/all/search?asset_types=GOOGLE_PLAY_APP_ID&ordering=Newest+programs")
        time.sleep(5)  # Wait for the JavaScript to load the content

        soup = BeautifulSoup(driver.page_source, 'html.parser')
        driver.quit()

        package_lst = []
        panels = soup.find_all('div', class_='Panel-module_u1-panel__javlC', limit=10)
        for panel in panels:
            footer = panel.find('footer', class_='flex flex-col justify-center px-md pb-md md:px-lg md:pb-lg h-3xl')
            if footer:
                link = footer.find('a', class_='Button-module_u1-button__OJmLM Button-module_u1-button--fill__dIsoD Button-module_u1-button--secondary__T13hl Button-module_u1-button--rounded-all__h9prY')
                if link:
                    scope_url = "https://hackerone.com" + link['href']
                    # https://hackerone.com/early_warning?type=team 이렇게 scope_url이 나오면
                    # https://hackerone.com/early_warning/policy_scopes 이렇게 바꿔줘야함
                    # early_warning이 아니라 다른게 와도 결국 ?type=team을 빼고 policy_scopes로 바꿔줘야함
                    print("before: ", scope_url)
                    if "?type=team" in scope_url:
                        scope_url = scope_url.replace("?type=team", "/policy_scopes")
                    print("after: ", scope_url)
                    package_name = self.get_package_name(scope_url)
                    print(package_name)
                    if package_name:
                        package_lst.append(package_name)

        return package_lst

    def get_package_name(self, scope_url):
        options = Options()
        options.headless = True
        service = ChromeService(executable_path=ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        driver.get(scope_url)
        time.sleep(5)  # Wait for the JavaScript to load the content

        soup = BeautifulSoup(driver.page_source, 'html.parser')
        # print(soup.prettify())
        driver.quit()

        asset_rows = soup.find_all('tr', class_='sc-fqkvVR spec-asset-row daisy-table__row')
        # print(asset_rows)
        for row in asset_rows:
            if row.find('td', class_='daisy-table__cell', text='Android: Play Store'):
                print("!!!!!!! find!!!!")
                cell = row.find('td', class_='daisy-table__cell', style='max-width: 400px;')
                if cell:
                    strong_tag = cell.find('strong')
                    if strong_tag and strong_tag.has_attr('title'):
                        print(strong_tag['title'])
                        return strong_tag['title']
                    else:
                        div_tag = cell.find('div', class_='interactive-markdown break-word markdownable daisy-helper-text')
                        if div_tag:
                            inner_div = div_tag.find('div', class_='vertical-spacing interactive_markdown_p')
                            if inner_div:
                                strong_tag = inner_div.find('strong')
                                if strong_tag:
                                    content = strong_tag.get_text().strip()
                                    package_name = content.split()[-1]
                                    return package_name
        return None

    def run(self):
        with open('/Users/j_j.ahn/Git_clone/ASAP/src/doc/target.txt', 'r') as file:
            targets = [line.strip() for line in file.readlines()]

        if not targets:
            print("No targets found in target.txt. Searching hackerone for targets.")
            targets = self.search_hackerone()
            print(targets)
            if not targets:
                print("Sorry Our program can't find any targets in hackerone because of the change in the website structure. Please write the target in target.txt.")

        for target in targets:
            print(f"Downloading {target}...")
            self.download_apk(target)

if __name__ == "__main__":
    print("------------------------------------------APK Downloader-------------------------------------------")
    print("|---APK Downloader, if you want to download apk, please enter the target in /src/docs/target.txt---|")
    print("|But if you don't write anything in target.txt, the program will search hackerone and download apk.|")
    print("-----------------------------------------------------------------------------------------------------")

    downloader = ApkDownloader()
    downloader.run()