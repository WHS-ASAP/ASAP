from modules.utils import string_list, ExtractContent
import xml.etree.ElementTree as ET
import re, os


class HardCodedAnalyzer:
    def __init__(self):
        self.java_string = list(string_list.java_analysis_regex)
        self.xml_string = list(string_list.xml_analysis_string)
        self.child_regex = re.compile(r'child\(["\']([^"\']+)["\']\)')
        self.ignore_file_path = ["kotlin"]

    def file_open(self, data, append=False):
        mode = "a" if append else "w"
        with open("./modules/result.txt", mode, encoding="utf-8") as f:
            f.write(data + "\n")

    def xml_analyzer(self, content):
        result = {}
        root = ET.fromstring(content)

        for string in root.findall("string"):
            name = string.get("name")
            value = string.text
            if any(item.lower() in name.lower() for item in self.xml_string):
                if "firebase" in name:
                    self.file_open(value, append=True)
                else:
                    result[name] = value
        return result

    def java_analyzer(self, content):
        result = {}
        lines = content.split("\n")
        for line_num, line in enumerate(lines, start=1):
            for pattern in self.java_string:
                res = re.search(pattern, line, re.IGNORECASE)
                if res:
                    # 모든 child() 호출을 탐지
                    child_matches = self.child_regex.findall(line)
                    if child_matches:
                        path = ""
                        for child in child_matches:
                            path = f"{path}/{child}".strip("/")
                            self.file_open(path, append=True)
                    else:
                        result[f"line low : {line_num}"] = line.lstrip()
        return result

    def is_need_file(self, file_path):
        ignore_file_path = ["/kotlin/"]
        for ignore in ignore_file_path:
            if ignore in file_path:
                return False

        norm_path = os.path.normpath(file_path)
        return norm_path.endswith(
            os.path.sep + "values" + os.path.sep + "strings.xml"
        ) or norm_path.endswith(".java")

    def run(self, file_path):

        result = {}

        if not self.is_need_file(file_path):
            return None

        extractor = ExtractContent(file_path)
        content = extractor.extract_content()
        if os.path.join("values", "strings.xml") in file_path:
            result.update(self.xml_analyzer(content))
        else:
            result.update(self.java_analyzer(content))
        if result:
            return result
        return None
