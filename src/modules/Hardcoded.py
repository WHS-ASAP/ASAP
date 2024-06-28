import re
import requests as r

data = {
    re.compile(r'<string name="(.*?)">(https://[a-zA-Z0-9.-]+.firebaseio\.com)</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(twiter.*[1-9][0-9]+-[0-9a-zA-Z]{40})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(twiter(.{0,20})?[\'"][0-9a-z]{18,25})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(twiter.*[\'|"][0-9a-zA-Z]{35,44})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(twiter(.{0,20})?[\'"][0-9a-z]{35,44})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">((?:\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">((?:\s|=|:|\"|^)AP[\dABCDEF][a-zA-Z0-9]{8,})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(bearer\s[a-zA-Z0-9_\-:\.=]+)</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(AKIA[0-9A-Z]{16})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">((?<=://)[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+)</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+)</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(((?:N|M|O)[a-zA-Z0-9]{23}\.[a-zA-Z0-9-_]{6}\.[a-zA-Z0-9-_]{27})$)</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(EAACEdEose0cBA[0-9A-Za-z]+)</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(facebook(.{0,20})?[\'"][0-9]{13,17})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(facebook.*[\'|"][0-9a-f]{32}[\'|"])</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(facebookfb(.{0,20})?[\'"][0-9a-f]{32})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(api_?key.*[\'|"][0-9a-zA-Z]{32,45}[\'|"])</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(github.*[\'|"][0-9a-zA-Z]{35,40}[\'|"])</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(([a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@github.com*)$)</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(AIza[0-9A-Za-z\-_]{35})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(\"type\": \"service_account\")</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(ya29\.[0-9A-Za-z\-_]+)</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">((([0-9A-Fa-f]{2}[:]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{2}[-]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{4}[\.]){2}[0-9A-Fa-f]{4})$)</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">([0-9a-f]{32}-us[0-9]{1,2})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(key-[0-9a-zA-Z]{32})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">((?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+)</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">([a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["\'\s])</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(sk_live_[0-9a-z]{32})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">((xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}))</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(sq0atp-[0-9A-Za-z\-_]{22})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(sq0csp-[0-9A-Za-z\-_]{43})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(sk_live_[0-9a-zA-Z]{24})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(rk_live_[0-9a-zA-Z]{24})</string>', re.IGNORECASE),
    re.compile(r'<string name="(.*?)">(SK[0-9a-fA-F]{32})</string>', re.I)
}


class HardCodedAnalyzer:
    def __init__(self):
        pass

    def _firebase_Parsing(self, content):
        res = r.get(content + '/.json')
        if res.status_code == 200:
            data = "Firebase access Enable"
            print(data)
        elif res.status_code == 423:
            data = "Firebase access Disable"
            print(data)
        elif res.status_code == 403:
            data = "Firebase access Permission Denied"
            print(data)
        else:
            data = "Firebase access Error"
            print(data)
        return data

    def run(self, file_content):
        HardCoded_results = []
        firebase_res = ''
        for pattern in data:
            matches = pattern.finditer(file_content.lower())
            for match in matches:
                name = match.group(1)
                value = match.group(2)
                if name in 'firebase_database_url':
                    firebase_res = f'{value} : {self._firebase_Parsing(value)}'
                    HardCoded_results.append(firebase_res)                                     
                else:
                    HardCoded_results.append(f'name: {name}, value: {value}')
        print(HardCoded_results)
        return HardCoded_results if HardCoded_results else None

if __name__ == "__main__":
    pass