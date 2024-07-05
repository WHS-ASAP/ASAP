import re
import os

class WebViewAnalyzer:

    def __init__(self):
        self.java_dir = 'java_src'
        self.activity_pattern = re.compile(r'activity[^<>]*exported="true"[^<>]* ', re.IGNORECASE)
        self.getExtra_pattern = re.compile(r"get[^()\n]*Extra", re.IGNORECASE)
        self.getintent_pattern = re.compile(r"getIntent", re.IGNORECASE)
        self.parseIntent_pattern = re.compile(r"parseIntent", re.IGNORECASE)
        self.loadurl_pattern = re.compile(r"loadurl", re.IGNORECASE)
        self.loadData_pattern = re.compile(r"loadData[^)\n]*text/html", re.IGNORECASE)
        self.shouldOverrideUrlLoading_pattern = re.compile(r'shouldOverrideUrlLoading', re.IGNORECASE)
        self.javascriptinterface_pattern = re.compile(r'@JavascriptInterface', re.IGNORECASE)
        self.setjavascriptenabled_pattern = re.compile(r'setjavascriptenabled', re.IGNORECASE)
        self.addJavascriptInterface_pattern = re.compile(r'addJavascriptInterface', re.IGNORECASE)
        self.setAllowFileAccessFromFileURLs_pattern = re.compile(r'setAllowFileAccessFromFileURLs\(true\)', re.IGNORECASE)
        self.allowuniversalaccess_pattern = re.compile(r'setAllowUniversalAccessFromFileURLs\(true\)', re.IGNORECASE)
        self.setallowFileaccess_pattern = re.compile(r'setAllowFileAccess', re.IGNORECASE)
        self.setAllowContentAccess_pattern = re.compile(r'setAllowContentAccess', re.IGNORECASE)
        self.metadata_pattern = re.compile(r'@metadata', re.IGNORECASE)
        self.hardcoded_pattern = re.compile(r'[^(]https://[^"'']', re.IGNORECASE)

    def exported_activity(self, content):
        matches = self.activity_pattern.findall(content)
        result = []
        for match in matches:
            patterns = re.compile(r'android:name="([^"]*)"', re.IGNORECASE)
            name_extract = patterns.search(match)
            if name_extract:
                name_string = name_extract.group(1)
                result.append(name_string)
        return result

    def analyze_activity(self, activity):
        try:
            with open(activity, 'r', encoding='utf-8') as file:
                sources = file.read()
                return sources
        except UnicodeDecodeError:
            return False

    def extract_lines_with_patterns(self, sources):
        lines = sources.split("\n")
        webview_result = []
        js_result = []
        fileaccess_result = []
        intent_result = []

        for line_num, line in enumerate(lines):
            if self.getExtra_pattern.findall(line) or self.getintent_pattern.findall(line) or self.parseIntent_pattern.findall(line):
                intent_result = (line.strip())
            
            if (self.loadurl_pattern.findall(line) or self.shouldOverrideUrlLoading_pattern.findall(line)) and not self.metadata_pattern.findall(line):
                if intent_result and intent_result[0] != line_num: #line_num이 같으면 출력하지 않음
                    webview_result.append(intent_result)
                    intent_result = ()

            if self.setAllowFileAccessFromFileURLs_pattern.findall(line) or self.allowuniversalaccess_pattern.findall(line) or self.setallowFileaccess_pattern.search(line):
                if webview_result:
                    fileaccess_result.append((line.strip()))
            
            if self.setjavascriptenabled_pattern.findall(line) or self.javascriptinterface_pattern.findall(line):
                if webview_result:
                    js_result.append((line.strip()))

        return webview_result, js_result, fileaccess_result

    def run(self, content):
        result = self.exported_activity(content)
        self.output = []
        result_dict = {}
        for activity in result:
            package = content.split("package=")[1].split('"')[1]
            activity_path = activity.replace('.', os.sep) + ".java"
            base_path = os.getcwd()
            whole_path = os.path.join(base_path, "java_src", package, "sources", activity_path)
            if os.path.exists(whole_path):
                sources = self.analyze_activity(whole_path)
                if sources:
                    webview_lines, js_lines, fileaccess_lines = self.extract_lines_with_patterns(sources)
                    if webview_lines:
                        result_dict = {
                            "activity": activity,
                            "webview_lines": webview_lines,
                            "javascript_lines": js_lines,
                            "fileaccess_lines": fileaccess_lines
                        }
                        self.output.append(result_dict)
            else:
                pass

        return self.output
