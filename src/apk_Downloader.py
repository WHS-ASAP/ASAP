import asyncio
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
import os
import urllib.request
from tqdm import tqdm
import ssl

# SSL 인증서 검증 무시 설정
context = ssl._create_unverified_context()


async def download_apk(url, package_name):
    """APK 파일 다운로드 함수"""
    if not os.path.exists("apk_dir"):
        os.makedirs("apk_dir")
        print("📁 다운로드 디렉토리 생성: apk_dir")

    file_path = os.path.join("apk_dir", f"{package_name}.apk")

    # 이미 다운로드된 파일이 있는지 확인
    if os.path.exists(file_path):
        print(f"ℹ️  {package_name}.apk가 이미 존재합니다. 건너뜁니다.")
        return True

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, context=context) as response:
            total_size = int(response.headers.get("Content-Length", 0))

            with open(file_path, "wb") as f, tqdm(
                desc=f"⬇️ {package_name}.apk 다운로드 중",
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

        print(f"✅ 다운로드 완료: {file_path}")
        return True
    except Exception as e:
        print(f"❌ 다운로드 중 오류 발생: {str(e)}")
        if os.path.exists(file_path):
            os.remove(file_path)
        return False


async def search_and_download_apk(package_name):
    """앱 검색 및 APK 다운로드 함수"""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        )
        page = await context.new_page()

        try:
            print(f"\n📱 패키지 처리 시작: {package_name}")
            await page.goto("https://apkcombo.com/ko/")
            await page.wait_for_load_state("networkidle")

            print(f"🔎 '{package_name}' 검색 중...")
            await page.wait_for_selector('input.ainput.awesomplete[name="q"]')
            await page.fill('input.ainput.awesomplete[name="q"]', package_name)

            await page.wait_for_selector("button.button.button-search.is-link")
            await page.click("button.button.button-search.is-link")

            await page.wait_for_load_state("networkidle")
            await page.wait_for_timeout(3000)

            print("🔍 검색 결과에서 앱 링크 찾는 중...")
            content = await page.content()
            soup = BeautifulSoup(content, "html.parser")

            app_link = soup.find("a", class_="button is-success is-fullwidth")

            if app_link and "href" in app_link.attrs:
                app_url = f"https://apkcombo.com{app_link['href']}"
                print(f"✅ 앱 페이지 발견: {app_url}")

                await page.goto(app_url)
                await page.wait_for_load_state("networkidle")
                await page.wait_for_selector(".file-list")

                print("🔍 APK 파일 검색 중...")
                content = await page.content()
                soup = BeautifulSoup(content, "html.parser")

                file_list = soup.find("ul", class_="file-list")
                if file_list:
                    apk_link = None
                    for link in file_list.find_all("a", class_="variant octs"):
                        if "href" in link.attrs and not "XAPK" in link.get_text():
                            apk_link = link["href"]
                            break

                    if apk_link:
                        print(f"✅ APK 다운로드 링크 발견")
                        await browser.close()
                        return await download_apk(apk_link, package_name)
                    else:
                        print(
                            "⚠️ APK 파일을 찾을 수 없습니다. XAPK 파일만 존재하거나 다른 형식일 수 있습니다."
                        )
                        print("❗ 수동으로 다운로드해주시기 바랍니다.")
                        await browser.close()
                        return False
                else:
                    print("❌ 파일 목록을 찾을 수 없습니다.")
                    await browser.close()
                    return False
            else:
                print("❌ 앱 링크를 찾을 수 없습니다.")
                await browser.close()
                return False

        except Exception as e:
            print(f"❌ 오류 발생: {str(e)}")
            await browser.close()
            return False


async def process_target_file():
    """target.txt 파일에서 패키지 목록을 읽고 처리"""
    target_file = os.path.join("docs", "target.txt")

    if not os.path.exists(target_file):
        print(f"❌ target.txt 파일을 찾을 수 없습니다: {target_file}")
        return

    try:
        with open(target_file, "r") as f:
            packages = [line.strip() for line in f.readlines() if line.strip()]

        if not packages:
            print("⚠️ target.txt 파일이 비어있습니다.")
            return

        print(f"📋 총 {len(packages)}개의 앱 패키지를 처리합니다.")

        for package in packages:
            success = await search_and_download_apk(package)
            if not success:
                print(f"⚠️ {package}는 수동으로 다운로드가 필요할 수 있습니다.")
            print("-" * 50)

        print("\n✅ 모든 패키지 처리 완료")

    except Exception as e:
        print(f"❌ target.txt 파일 처리 중 오류 발생: {str(e)}")


async def main():
    print("----------------------------------------")
    print("APKCombo Downloader")
    print("Target file: docs/target.txt")
    print("Download directory: apk_dir")
    print("----------------------------------------")

    await process_target_file()


if __name__ == "__main__":
    asyncio.run(main())
