import os
import re
import requests


class FilePathCheck:
    def __init__(self, file_path):
        self.file_path = file_path
        self.tmp_lst = file_path.split(os.sep)
        self.origin_package_name = self.tmp_lst[1]

    def check_shared_and_pref(self):
        return "shared" in self.file_path and "pref" in self.file_path

    def validate(self):
        # if self.check_shared_and_pref() or self.check_path():
        if self.check_shared_and_pref():
            return self.file_path
        return None

class firebase:
    def __init__(self):
        self.file_path = './modules/result.txt'

    def firebase_parsing(self):
        i = 1
        child = []
        with open(self.file_path, 'r') as f:
            lines  = f.readlines()
            for line in lines:
                if line.startswith('https:/'):
                    url = line.strip()
                else:
                    child.append(line.strip())
                    i += 1
        return url, child
    
    def firebase_connect(self):
        url, childs = self.firebase_parsing()
        res = requests.get(f'{url}/.json')
        if childs:
            for child in childs:
                res = requests.get(f'{url}/{child}/.json')
                print(res.status_code)
            

                
        
class string_list:
    java_analysis_regex = [
        r"//s3-[a-z0-9-]+\.amazonaws\.com/[a-z0-9._-]+",
        r"//s3\.amazonaws\.com/[a-z0-9._-]+",
        r"[a-z0-9.-]+\.s3-[a-z0-9-]\.amazonaws\.com",
        r"[a-z0-9.-]+\.s3-website[.-](eu|ap|us|ca|sa|cn)",
        r"[a-z0-9.-]+\.s3\.amazonaws\.com",
        r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        r"(?:\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}",
        r"bearer\s[a-zA-Z0-9_\-:\.=]+",
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
        r"\.child\(" 
    ]

    xml_analysis_string = [
        'AWS', 'Amazon','Access_Key_ID', 'S3_Bucket','Facebook_Access_Token','Facebook_ClientID', 'Facebook_OAuth', 'Facebook_Secret_Key', 'firebase_database_url', 'Amazon_AWS_Access_Key_ID', 'Discord_BOT_Token', 'Twitter_Secret_Key',
        'Twitter_oauth', 'Twitter_clientid', 'Twitter_access_token', 'Twilio_api_key', 'SSH', 'slack_token', 'Json_Web_Token',
        'Google_OAuth_Access_Token', 'Google_Cloud_Platform_OAuth', 'Google_Cloud_Platform_Service_Account' 'GitHub', 'Artifactory'
    ]


class ExtractContent:
    def __init__(self, file_path):
        self.file_path = file_path

    def extract_content(self):
        with open(self.file_path, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
            return content
