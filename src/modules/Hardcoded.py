import re
import requests as r
from modules.utils import string_list

class HardCodedAnalyzer:
    def __init__(self):
        self.string = string_list.analysis_regex
        self.cache = {}
        
    def firebase_connect(self, uri):
        data = ''
        if uri in self.cache:
            return
        res = r.get(uri)
        if res.status_code == 200:
            data = "Firebase access enabled"
            self.cache[uri] = data
            return data
        else:
            data = res.text
            self.cache[uri] = data
            return data
    
    def analyzer(self, content):
        self.xml_results = {}
        url = ''
        xml_pattern = r'<string\s+name=(\".*?\")>(.*?)</string>'
        lines = content.split('\n')
        for line in lines:
            for pattern in self.string:
                res = re.search(pattern, line,re.I)
                if res:
                    try:
                        if "</string>" in line:
                            self.xml_match = re.search(xml_pattern, line, re.I)
                            if self.xml_match.group(1) == '"firebase_database_url"':
                                url = self.xml_match.group(2)
                                self.xml_results[url] = self.firebase_connect(url+'/.json').strip()
                            else:
                                match1, match2 = self.xml_match.group(1), self.xml_match.group(2)
                                self.xml_results[match1] = match2
                        else:
                            raise
                    except:
                        if "child(" in res.group():
                            child_match = re.search(r'child\(["\']([^"\']+)["\']\)', line)
                            if child_match:
                                child = child_match.group(1)
                                self.xml_results['firebase_child'] = child
                        else:
                            self.xml_results['java'] = line.lstrip()
        return self.xml_results
    
    def run(self, content):
        xml_result = self.analyzer(content)
        if xml_result:
            return xml_result
        return None