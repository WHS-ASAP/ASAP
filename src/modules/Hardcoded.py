import re
import requests as r
from modules.utils import string_list

class HardCodedAnalyzer:
    def __init__(self):
        self.string_regex = string_list.analysis_regex
        self.url = ''
        self.child = ''
        self.cache = {}  # 캐시를 위한 딕셔너리
        
    def firebase_connect(self, uri, collect):
        data = ''
        if uri == '':
            return 
        elif collect == '':
            uri = f'{uri}/.json'
        else:
            uri = f'{uri}/{collect}/.json'
        
        if uri in self.cache:
            return
        res = r.get(uri)
        if res.status_code == 200:
            data = "Firebase access enabled"
            self.cache[uri] = data  # 응답을 캐시에 저장
            return data
        else:
            data = res.text
            self.cache[uri] = data
            return self.cache
    
    def analyzer(self, content):
        results = []
        fire_res = ''
        lines = content.split('\n')
        for line in lines:
            for pattern in self.string_regex:
                res = re.search(pattern, line)
                if res:
                    line = line.replace('<','&lt;')
                    line = line.replace('>','&gt;')
                    results.append(line.lstrip())
                    try:
                        if 'firebaseio' in res.group():
                            self.url = res.group()
                        if "child(" in res.group():
                            child_match = re.search(r'child\(["\']([^"\']+)["\']\)', res.group())
                            if child_match:
                                self.child = child_match.group(1)
                        else:
                            raise
                    except:
                        pass
        if self.url != '':
            fire_res = self.firebase_connect(self.url, self.child)
        return results, fire_res
      
    def run(self, content):
        results, fire_res = self.analyzer(content)
        if results and fire_res:
            return results, fire_res
        return None


if __name__ == "__main__":
    pass