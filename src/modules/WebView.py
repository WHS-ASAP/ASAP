import re
import os
from modules.utils import ExtractContent
from modules.Permission import PermissionAnalyzer

# 웹뷰기능 활성화 탐지 O
# js기능 활성화 탐지 O
# fileaccess true 탐지 O
# js기능이 활성화되어있을 때 javascriptinterface가 적용된 함수명이 잘 나오는지 O
# permission이 잘 나오는지 O
# 안드로이드 스튜디오로 만들어지지 않은 앱 액티비티가 없는 앱?-정적분석으로 탐지할 수 있는 방법??? frida 후킹,.., java php / 기본적인걸 막아주는 프레임 워크 node js/flutter/react natvie/kiri처럼 나오는거


class WebViewAnalyzer:

    def __init__(self):
        self.java_dir = "java_src"
        self.activity_pattern = re.compile(
            r'activity[^<>]*exported="true"[^<>]* ', re.IGNORECASE
        )
        self.getExtra_pattern = re.compile(r"getStringExtra", re.IGNORECASE)
        self.getExtras_pattern = re.compile(r"getStringExtras", re.IGNORECASE)
        self.getintent_pattern = re.compile(r"getIntent", re.IGNORECASE)
        self.parseIntent_pattern = re.compile(r"parseIntent", re.IGNORECASE)
        self.loadurl_pattern = re.compile(r"loadurl", re.IGNORECASE)
        self.loadData_pattern = re.compile(r"loadData[^)\n]*text/html", re.IGNORECASE)
        self.shouldOverrideUrlLoading_pattern = re.compile(
            r"shouldOverrideUrlLoading", re.IGNORECASE
        )
        self.javascriptinterface_pattern = re.compile(
            r"@JavascriptInterface", re.IGNORECASE
        )
        self.setjavascriptenabled_pattern = re.compile(
            r"setjavascriptenabled", re.IGNORECASE
        )
        self.addJavascriptInterface_pattern = re.compile(
            r"addJavascriptInterface", re.IGNORECASE
        )
        self.setAllowFileAccessFromFileURLs_pattern = re.compile(
            r"setAllowFileAccessFromFileURLs\(true\)", re.IGNORECASE
        )
        self.allowuniversalaccess_pattern = re.compile(
            r"setAllowUniversalAccessFromFileURLs\(true\)", re.IGNORECASE
        )
        self.setallowFileaccess_pattern = re.compile(
            r"setAllowFileAccess(true)", re.IGNORECASE
        )
        self.setAllowContentAccess_pattern = re.compile(
            r"setAllowContentAccess", re.IGNORECASE
        )
        self.metadata_pattern = re.compile(r"@metadata", re.IGNORECASE)
        self.hardcoded_pattern = re.compile(r'[^(]https://[^"' "]", re.IGNORECASE)
        self.imported_file_pattern = re.compile(
            r"(?<=import\s)com.[\w.]+(?=;)", re.IGNORECASE
        )

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
            with open(activity, "r", encoding="utf-8") as file:
                sources = file.read()
                return sources
        except UnicodeDecodeError:
            return False

    def extract_lines_with_webview_patterns(self, whole_path):
        sources = ExtractContent(whole_path).extract_content()
        lines = sources.split("\n")
        webview_result = []
        intent_result = []
        intent_line = -1

        for line_num, line in enumerate(lines):
            if (
                self.getExtra_pattern.findall(line)
                or self.getintent_pattern.findall(line)
                or self.parseIntent_pattern.findall(line)
            ):
                intent_result.append(line.strip())
                intent_line = line_num
            if (
                self.loadurl_pattern.findall(line)
                or self.shouldOverrideUrlLoading_pattern.findall(line)
            ) and not self.metadata_pattern.findall(line):
                if intent_result and intent_line != line_num:
                    webview_result.extend(intent_result)
                    webview_result.append(line.strip())
                    intent_result = []
                elif intent_result and intent_line == line_num:
                    webview_result.append(line.strip())
                else:
                    intent_result = []

        return webview_result

    def extract_lines_with_fileaccess_patterns(self, sources):
        lines = sources.split("\n")
        fileaccess_result = []
        for line_num, line in enumerate(lines):
            if (
                self.setAllowFileAccessFromFileURLs_pattern.findall(line)
                or self.allowuniversalaccess_pattern.findall(line)
                or self.setallowFileaccess_pattern.search(line)
            ):
                fileaccess_result.append(line.strip())
        return fileaccess_result

    def javascript_analysis(self, file_path):
        content = ExtractContent(file_path).extract_content()
        js_result = set()  # 중복 방지를 위해 set 사용
        if content:
            lines = content.split("\n")
            for line_num, line in enumerate(lines):
                if self.javascriptinterface_pattern.findall(line):
                    js_func = lines[line_num + 1].strip()
                    match = re.search(r"(\w+)\s*\([^)]*\)\s*\{", js_func)
                    if match:
                        js_result.add(match.group(1))  # set에 추가하여 중복 방지
        return list(js_result)  # 리스트로 반환

    def imported_file(self, file_path):
        content = ExtractContent(file_path).extract_content()
        imported_result = set()
        if content:
            lines = content.split("\n")
            for line_num, line in enumerate(lines):
                imported_files = self.imported_file_pattern.findall(line)
                for imported_file in imported_files:
                    imported_result.add(imported_file)
        return list(imported_result)

    def permissions_in_app_webview(self, xml_path, keyword):
        analyzer = PermissionAnalyzer()
        dangerous_keywords, dangerous_permissions = analyzer.run_jsmethod(
            xml_path, keyword
        )
        return dangerous_keywords, dangerous_permissions

    def permissions_and_scheme(self, xml_path):
        analyzer = PermissionAnalyzer()
        dangerous_permissions = analyzer.run(xml_path)
        return dangerous_permissions

    def run(self, file_path):
        js_result = []
        webview_lines = []
        if file_path.endswith("AndroidManifest.xml"):
            content = ExtractContent(file_path).extract_content()
            exported_activities = self.exported_activity(content)
            self.output = []
            result_dict = {}
            for activity in exported_activities:
                package = file_path.split(f"java_src{os.sep}")[1].split(
                    f"{os.sep}resources"
                )[0]
                activity_path = activity.replace(".", os.sep) + ".java"
                base_path = os.getcwd()
                whole_path = os.path.join(
                    base_path, "java_src", package, "sources", activity_path
                )
                if os.path.exists(whole_path):
                    webview_lines = self.extract_lines_with_webview_patterns(whole_path)
                    fileaccess_lines = self.extract_lines_with_fileaccess_patterns(
                        ExtractContent(whole_path).extract_content()
                    )
                    if webview_lines:
                        suspicious_path = whole_path
                        js_result.extend(self.javascript_analysis(suspicious_path))
                        imported_files = self.imported_file(suspicious_path)
                        dangerous_info = self.permissions_and_scheme(file_path)
                        for imported_file in imported_files:
                            whole_path = os.path.join(
                                base_path,
                                "java_src",
                                package,
                                "sources",
                                imported_file.replace(".", os.sep) + ".java",
                            )
                            js_result.extend(self.javascript_analysis(whole_path))
                            js_result = list(set(js_result))
                            dangerous_keywords = []
                            dangerous_permission = []

                            if js_result:
                                dangerous_keywords, dangerous_permission = (
                                    self.permissions_in_app_webview(
                                        file_path, js_result
                                    )
                                )
                                dangerous_keywords = list(set(dangerous_keywords))
                                dangerous_permission = list(set(dangerous_permission))

                        result_dict = {
                            "activity": activity,
                            "webview_lines": webview_lines,
                            "fileaccess_lines": fileaccess_lines,
                            "javascript_lines": list(set(js_result)),
                            "vulnerable_info_in_your_device": dangerous_info,
                            "permission with javascript_lines": (
                                dangerous_keywords,
                                dangerous_permission,
                            ),
                        }
                        self.output.append(result_dict)
                        return self.output
        else:
            pass
