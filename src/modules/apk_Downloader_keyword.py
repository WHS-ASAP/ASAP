import os
import requests
from tqdm import tqdm
from bs4 import BeautifulSoup

class APKPureDownloader:
    def __init__(self, query):
        self.query = query
        self.base_search_url = "https://apkpure.com/search?q="
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
        }

    def search_apk_pure(self):
        search_url = f"{self.base_search_url}{self.query}"
        response = requests.get(search_url, headers=self.headers)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            first_result = soup.find('a', class_='da')
            if first_result:
                app_url = first_result['href']
                return app_url
        return None

    def get_download_link(self, app_page_url):
        response = requests.get(app_page_url, headers=self.headers)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Option 1
            download_link_tag = soup.find('a', class_='btn download-start-btn')
            if download_link_tag:
                download_link = download_link_tag['href']
                return download_link
            # Option 2: Option 1에서 다운로드 링크 태그를 찾지 못한 경우
            download_btn = soup.find('a', class_='download_apk_news')
            if download_btn:
                package_name = download_btn.get('data-dt-package_name')
                print(f"Package name: {package_name}")
                if package_name:
                    return f"https://d.apkpure.com/b/APK/{package_name}?version=latest"
        return None

    def download_apk(self, download_url):
        response = requests.get(download_url, headers=self.headers, stream=True)
        if response.status_code == 200:
            
            if not os.path.exists('apk_dir'):
                os.makedirs('apk_dir')

            apk_path = os.path.join('apk_dir', f"{self.query}.apk")
            
            # APK가 이미 존재하는지 확인
            if os.path.exists(apk_path):
                print(f"{self.query} already exists in apk_dir. Skipping download.")
                return

            # APK 파일의 총 크기 가져오기
            total_size = int(response.headers.get('content-length', 0))

            # Download 시각화 
            with open(apk_path, 'wb') as file, tqdm(
                desc=f"Downloading {self.query}",
                total=total_size,
                unit='iB',
                unit_scale=True,
                unit_divisor=1024,
            ) as bar:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        file.write(chunk)
                        bar.update(len(chunk))

            print(f"\nDownloaded {self.query} to {apk_path}")
        else:
            print(f"Failed to download {self.query}. Status code: {response.status_code}")

    def run(self):
        app_page_url = self.search_apk_pure()
        if app_page_url:
            download_link = self.get_download_link(app_page_url)
            if download_link:
                self.download_apk(download_link)
            else:
                print("Failed to find the download link on the app's page.")
        else:
            print("Failed to find the app on APKPure.")

if __name__ == "__main__":
    app_query = input("Enter the app name or related keyword: ")
    downloader = APKPureDownloader(app_query)
    downloader.run()
