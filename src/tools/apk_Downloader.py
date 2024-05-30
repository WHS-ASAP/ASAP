import os
import time
import asyncio
from tqdm import tqdm
from bs4 import BeautifulSoup
import urllib.request
from playwright.async_api import async_playwright

class ApkDownloader:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        }
        self.base_apkpure_url = "https://d.apkpure.com/b/APK/"

    async def download_apk(self, package_name):
        download_url = f"{self.base_apkpure_url}{package_name}?version=latest"
        # check download url
        print(download_url)

        # Retry logic because the download might fail due to network issues
        max_retries = 3 # Maximum number of retries 
        retry_delay = 5 # Retry delay in seconds

        # Retry loop
        for attempt in range(max_retries):
            try:
                req = urllib.request.Request(download_url, headers=self.headers)
                with urllib.request.urlopen(req) as response:
                    if response.status == 200:
                        if not os.path.exists('apk_dir'):
                            os.makedirs('apk_dir')

                        apk_path = os.path.join('apk_dir', f"{package_name}.apk")

                        # Check if the APK already exists in the apk_dir
                        if os.path.exists(apk_path):
                            print(f"{package_name} already exists in apk_dir. Skipping download.")
                            return

                        total_size = int(response.getheader('Content-Length', 0))
                        # view download progress (visualize the download progress with tqdm)
                        with open(apk_path, 'wb') as file, tqdm(
                            desc=f"Downloading {package_name}",
                            total=total_size,
                            unit='iB',
                            unit_scale=True,
                            unit_divisor=1024, # 1KB
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
            # Retry the download if an exception occurs
            except Exception as e:
                print(f"Error: {e}")
                if attempt < max_retries - 1:
                    print(f"Retrying in {retry_delay} seconds...")
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    print(f"Exceeded maximum retries. Could not download {package_name}.")

    # Search for APKs on HackerOne
    async def search_hackerone(self):
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto("https://hackerone.com/opportunities/all/search?asset_types=GOOGLE_PLAY_APP_ID&ordering=Newest+programs")
            await page.wait_for_timeout(5000)  # Wait for the JavaScript to load the content

            content = await page.content()
            soup = BeautifulSoup(content, 'html.parser')
            await browser.close()

            package_lst = []
            panels = soup.find_all('div', class_='Panel-module_u1-panel__javlC')
            index = 0
            # length of package_lst : 10
            while len(package_lst) < 10 and index < len(panels):
                panel = panels[index]
                footer = panel.find('footer', class_='flex flex-col justify-center px-md pb-md md:px-lg md:pb-lg h-3xl')
                if footer:
                    link = footer.find('a', class_='Button-module_u1-button__OJmLM Button-module_u1-button--fill__dIsoD Button-module_u1-button--secondary__T13hl Button-module_u1-button--rounded-all__h9prY')
                    if link:
                        scope_url = "https://hackerone.com" + link['href']
                        # print("before: ", scope_url)
                        if "?type=team" in scope_url:
                            scope_url = scope_url.replace("?type=team", "/policy_scopes")
                        # print("after: ", scope_url)
                        package_name = await self.get_package_name(scope_url)
                        
                        # print(package_name)

                        # remove https://play.google.com/store/apps/details?id if it exists (processing)
                        if package_name and 'https://play.google.com/store/apps/details?id=' in package_name:
                            package_name = package_name.replace('https://play.google.com/store/apps/details?id=', '')

                        # check if the package name is valid
                        if package_name and ('.' in package_name and len(package_name.split('.')) > 1 and len(package_name) < 40):
                            print(f"Adding package name '{package_name}' to the list. Progress: {len(package_lst) + 1}/10")
                            package_lst.append(package_name)
                        else:
                            print(f"Package name '{package_name}' is invalid. Skipping. You may need to search manually.")
                
                index += 1 # next panel(next app)

            return package_lst

    # Get the package name from the HackerOne scope URL
    async def get_package_name(self, scope_url):
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(scope_url)
            await page.wait_for_timeout(5000)  # Wait for the JavaScript to load the content

            content = await page.content()
            soup = BeautifulSoup(content, 'html.parser')
            await browser.close()

            asset_rows = soup.find_all('tr', class_='sc-fqkvVR spec-asset-row daisy-table__row')
            for row in asset_rows:
                if row.find('td', class_='daisy-table__cell', string='Android: Play Store'):
                    # print("!!!!!!! find!!!!")
                    cell = row.find('td', class_='daisy-table__cell', style='max-width: 400px;')
                    if cell:
                        strong_tag = cell.find('strong')
                        if strong_tag and strong_tag.has_attr('title'):
                            # print("Find package name: ", strong_tag['title'])
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

    async def run(self):
        
        print("------------------------------------------APK Downloader--------------------------------------------")
        print("|---APK Downloader, if you want to download apk, please enter the target in /src/docs/target.txt---|")
        print("|But if you don't write anything in target.txt, the program will search hackerone and download apk.|")
        print("----------------------------------------------------------------------------------------------------")

        try:
            # User directory/ASAP path
            file_path = os.getcwd()
            
            # set target file path
            target_file_path = os.path.join(file_path, 'docs/target.txt')
            
            if not os.path.exists(target_file_path):
                print(f"Error: Target file not found at {target_file_path}")
                return
            
            with open(target_file_path, 'r') as file:
                targets = [line.strip() for line in file.readlines()]

            if not targets:
                print("No targets found in target.txt. Searching hackerone for targets.")
                targets = await self.search_hackerone()
                if not targets:
                    print("Sorry Our program can't find any targets in hackerone because of the change in the website structure. Please write the target in target.txt.")

            print(f"Downloading {len(targets)} APKs : {targets}...")
            download_tasks = [self.download_apk(target) for target in targets]
            await asyncio.gather(*download_tasks)

        except Exception as e:
            print(f"An error occurred: {e}")
            print("Trying to install browsers with playwright install")
            os.system("python -m playwright install") # if not installed, install browsers with playwright 
            print("Please rerun the script after the installation is complete.")    

    async def test(self):
        
        print("------------------------------------------APK Downloader--------------------------------------------")
        print("|---APK Downloader, if you want to download apk, please enter the target in /src/docs/target.txt---|")
        print("|But if you don't write anything in target.txt, the program will search hackerone and download apk.|")
        print("----------------------------------------------------------------------------------------------------")

        try:

            # set target current file path
            script_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(script_dir)
            target_file_path = os.path.join(parent_dir, 'docs', 'target.txt')

            if not os.path.exists(target_file_path):
                print(f"Error: Target file not found at {target_file_path}")
                return
            
            with open(target_file_path, 'r') as file:
                targets = [line.strip() for line in file.readlines()]

            if not targets:
                print("No targets found in target.txt. Searching hackerone for targets.")
                targets = await self.search_hackerone()
                if not targets:
                    print("Sorry Our program can't find any targets in hackerone because of the change in the website structure. Please write the target in target.txt.")

            print(f"Downloading {len(targets)} APKs : {targets}...")
            download_tasks = [self.download_apk(target) for target in targets]
            await asyncio.gather(*download_tasks)

        except Exception as e:
            print(f"An error occurred: {e}")
            print("Trying to install browsers with playwright install")
            os.system("python -m playwright install") # if not installed, install browsers with playwright 
            print("Please rerun the script after the installation is complete.")  


if __name__ == "__main__":
    
    downloader = ApkDownloader()
    asyncio.run(downloader.test())
