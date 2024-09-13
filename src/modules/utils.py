import os
import re
import requests


class Firebase:
    def __init__(self):
        self.file_path = './modules/result.txt'

    def load_urls(self):
        urls = []
        childs = []
        with open(self.file_path, 'r') as f:
            lines = f.readlines()
            for line in lines:
                url = line.strip()
                if url.startswith("https:/"):
                    urls.append(url)
                else:
                    childs.append(line.strip())
        return urls, childs

    def firebase_connect(self, urls, childs=None):
        data = {}
        for url in urls:
            try:
                res = requests.get(f"{url}/.json")
                if res.status_code == 200:
                    if res.text != "null":
                        data[url] = "Firebase data accessible"
                    else:
                        data[url] = "Firebase access enabled but no data"
                else:
                    data[url] = f"{res.text}"

                if childs:
                    for child in childs:
                        child_res = requests.get(f"{url}/{child}/.json")
                        if child_res.status_code == 200:
                            if child_res.text != "null":
                                data[f"{url}/{child}"] = "Child data accessible"
                            else:
                                data[f"{url}/{child}"] = "Child access enabled but no data"
                        else:
                            data[f"{url}/{child}"] = f"{child_res.text}"

            except Exception as e:
                data[url] = f"Exception occurred: {str(e)}"
        return data
    
    def run(self):
        urls, childs = self.load_urls()
        data = self.firebase_connect(urls, childs)
        return data

class string_list:
    java_analysis_regex = [
        r"//s3-[a-z0-9-]+\.amazonaws\.com/[a-z0-9._-]+",
        r"//s3\.amazonaws\.com/[a-z0-9._-]+",
        r"[a-z0-9.-]+\.s3-[a-z0-9-]\.amazonaws\.com",
        r"[a-z0-9.-]+\.s3-website[.-](eu|ap|us|ca|sa|cn)",
        r"[a-z0-9.-]+\.s3\.amazonaws\.com",
        r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        r"(?:\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}",
        r"bearer\s(?!.*bearer)[a-zA-Z0-9_\-:\.=]+"
        r"((?:N|M|O)[a-zA-Z0-9]{23}\.[a-zA-Z0-9-_]{6}\.[a-zA-Z0-9-_]{27})$",
        r"EAACEdEose0cBA[0-9A-Za-z]+",
        r"facebook(.{0,20})?['\"][0-9]{13,17}",
        r"facebook.*['|\"][0-9a-f]{32}['|\"]",
        r"(facebook)(.{0,20})?['\"][0-9a-f]{32}",
        r"[a-z0-9.-]+\.firebaseio\.com",
        r"([a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@github.com*)$",
        r"AIza[0-9A-Za-z\-_]{35}",
        r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        r"heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        r"(?i)^((?=.*[a-z])(?=.*[0-9])(?:[a-z0-9_=]+\.){2}(?:[a-z0-9_\-\+/=]*))$",
        r"(([0-9A-Fa-f]{2}[:]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{2}[-]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{4}[\.]){2}[0-9A-Fa-f]{4})$",
        r"(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+",
        r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}[\"'\s]",
        r'.child\(["\']([^"\']+)["\']\)'
    ]

    xml_analysis_string = [
        "Amazon",
        "Access_Key_ID",
        "S3_Bucket",
        "Facebook_Access_Token",
        "Facebook_ClientID",
        "Facebook_OAuth",
        "Facebook_Secret_Key",
        "firebase_database_url",
        "Amazon_AWS_Access_Key_ID",
        "Discord_BOT_Token",
        "Twitter_Secret_Key",
        "Twitter_oauth",
        "Twitter_clientid",
        "Twitter_access_token",
        "Twilio_api_key",
        "SSH",
        "slack_token",
        "Json_Web_Token",
        "Google_OAuth_Access_Token",
        "Google_Cloud_Platform_OAuth",
        "Google_Cloud_Platform_Service_Account" "GitHub",
        "Artifactory",
        "SECRET_KEY",
        "API_KEY",
        "API_TOKEN",
        "SECRET_TOKEN",
        "BEARER"
    ]

class ExtractContent:
    def __init__(self, file_path):
        self.file_path = file_path

    def extract_content(self):
        with open(self.file_path, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
            return content


class ExceptCPkeyword:
    def __init__(self):
        # facebook, google, firebase, amazon, slack, twitter 등의 키워드가 content://com.facebook.app.FacebookContentProvider 처럼 문장으로 들어오면 정규표현식을 만들어서 제외시키는 클래스

        self.regex = [
            r"com\.facebook\..*",
            r"com\.google\..*",
            r"com\.firebase\..*",
            r"com\.amazon\..*",
            r"com\.slack\..*",
            r"com\.twitter\..*",
            r"downloads/public_downloads",
            r"com.android.contacts",
            r"contacts/lookup/*",
            # 계속 추가 예정..
        ]

    def check(self, content):
        for reg in self.regex:
            if re.search(reg, content):
                return True
        return False