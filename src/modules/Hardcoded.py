from modules.utils import string_list, ExtractContent
import xml.etree.ElementTree as ET
import re, os

class HardCodedAnalyzer:
    def __init__(self):
        self.java_string = list(string_list.java_analysis_regex)
        self.xml_string = list(string_list.xml_analysis_string)
        
    def file_open(self, data, append=False):
        mode = 'a' if append else 'w'
        with open('./modules/result.txt', mode) as f:
            f.write(data + '\n')

    def xml_analyzer(self, content):
        result = {}
        root = ET.fromstring(content)

        for string in root.findall('string'):
            name = string.get('name')
            value = string.text
            if any(item.lower() in name.lower() for item in self.xml_string):
                if 'firebase' in name:
                    self.file_open(value, append=True)
                else:
                    result[name] = value
        return result

    def java_analyzer(self, content):
        result = {}
        lines = content.split('\n')
        for line_num, line in enumerate(lines, start=1):
            for pattern in self.java_string:
                res = re.search(pattern, line, re.IGNORECASE)
                if res:
                    if "child(" in res.group():
                        child_match = re.search(r'child\(["\']([^"\']+)["\']\)', line)
                        if child_match:
                            child = child_match.group(1)
                            self.file_open(child, append=True)  
                    else:
                        result[f'line low : {line_num}'] = line.lstrip()
        return result


        
    def run(self, file_path):
        result = {}
        if not any(file_path.endswith(ext) for ext in [os.path.join('values', 'strings.xml'), '.java']):
            return
        extractor = ExtractContent(file_path)
        content = extractor.extract_content()
        if os.path.join('values', 'strings.xml') in file_path:
            # print(f'start analysis {file_path}')
            result.update(self.xml_analyzer(content))
        else:
            # print(f'start analysis {file_path}')
            result.update(self.java_analyzer(content))
        if result:
            return result
        return None