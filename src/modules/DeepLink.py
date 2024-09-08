import re
import os
from modules.utils import ExtractContent
from modules.permission2 import PermissionAnalyzer

class DeepLinkAnalyzer:
    def __init__(self):
        self.java_dir = "java_src"
        self.activity_pattern = re.compile(r'<activity.*?>.*?</activity>', re.DOTALL)
        self.getQueryParameter_pattern = re.compile(r'getQueryParameter\(([^)]+)\)')
        self.scheme_pattern = re.compile(r'android:scheme="([^"]+)"', re.IGNORECASE)
        self.path_pattern=re.compile(r'android:path="([^"]+)"', re.IGNORECASE)
        self.host_pattern = re.compile(r'host', re.IGNORECASE)
        self.addURI_pattern = re.compile(r'\.addURI\(([^,]+),\s*"([^"]+)",\s*(\d+)\)', re.IGNORECASE)
        self.uriParse_pattern = re.compile(r'Uri\.parse\("([^"]*)"\)', re.IGNORECASE)
        #self.path_pattern=re.compile(r'"/([^"]+)"',re.IGNORECASE)

    def searching_activity(self, activities):
        results = []
        for activity in activities:
            activity_name_pattern = re.compile(r'android:name="([^"]*)"', re.IGNORECASE)
            activity_name = activity_name_pattern.search(activity)
            scheme_match = self.scheme_pattern.search(activity)
            path_match = self.path_pattern.search(activity)

            if activity_name and scheme_match:
                name_string = activity_name.group(1)
                scheme = scheme_match.group(1)
                path = path_match.group(1) if path_match else ''  # path가 없으면 빈 문자열 추가
                results.append((name_string, scheme, path))  # 항상 세 개의 값 반환

        return results if results else False

    def extract_lines_with_pattern(self, sources):
        #print('in extract_lines_with_pattern')
        lines = sources.split("\n")
        intent_result = []
        
        for line_num, line in enumerate(lines):
            
            get_query_match = self.getQueryParameter_pattern.search(line)
            get_addUri_match = self.addURI_pattern.search(line)
            get_uriParse_match = self.uriParse_pattern.search(line)
            
            if get_query_match:
                parameter = get_query_match.group(0).split('(')[1].split(')')[0]
                intent_result.append(parameter)
                
            if get_addUri_match:
                parameter1 = get_addUri_match.group(0).split(',')[1].split(')')[0]
                intent_result.append((parameter1))
                
            if get_uriParse_match:
                parameter = get_uriParse_match.group(0).split('(')[1].split(')')[0]
                intent_result.append(parameter)
                
        return intent_result
    
    def permissions_in_deeplink(self,xml_path, scheme_list):
        analyzer = PermissionAnalyzer()
        dangerous_keywords, dangerous_permissions = analyzer.run_deeplink(xml_path, scheme_list)
        return dangerous_keywords, dangerous_permissions
        
    def resolve_string_key(self, file_path, key):  # string key를 받아서 resolve
        if file_path.endswith("strings.xml"):
            #print(f'key{key}')
            content = ExtractContent(file_path).extract_content()
            string_list = content.split("<string ")
            real_scheme=[]
            for string in string_list:
                if "name=" in string:
                    #print(f'in string {string}')
                    name = string.split("name=")[1].split('"')[1]
                    if name==key:
                        value = string.split("name=")[1].split(">")[1].split("<")[0]
                        real_scheme.append(value)
                        #print(f'real scheme {value}')
                    
            return real_scheme  # 해당 key의 값이 없으면 key 자체를 반환

        
    def resolve_variables(self, file_path, content):
        # content가 튜플일 경우 문자열로 변환
        if isinstance(content, tuple):
            content = " ".join(content)

        # content를 이스케이프 처리하고 정규 표현식을 사용하여 값 추출
        pattern = re.compile(rf'{re.escape(content)}=(.*)')
        file_content = ExtractContent(file_path).extract_content()
        
        if file_content:
            for line in file_content.split("\n"):
                match = pattern.search(line)
                if match:
                    return match.group(1)
        return None

    def run(self, file_path):
        search_path = []
        scheme_list = []
        path_list=[]
        deeplink_params=[]
        if file_path.endswith("AndroidManifest.xml"):
            #print('in_androidmanifest')
            content = ExtractContent(file_path).extract_content()
            activities = self.activity_pattern.findall(content)
            activity_schemes = self.searching_activity(activities)
            #print(f"Activity schemes: {activity_schemes}")
            if activity_schemes:
                for activity, scheme, path in activity_schemes:
                    search_path.append(activity)

                    if "@string/" in scheme:
                        key = scheme.split("@string/")[1]
                        package = file_path.split("java_src\\")[1].split("\\resources")[0]
                        xml_file = os.path.join(os.getcwd(), "java_src", package, "resources", "res", "values", "strings.xml")
                        real_scheme = self.resolve_string_key(xml_file, key)
                        scheme_list.append(real_scheme if real_scheme else scheme)
                        
                    else:
                        scheme_list.append(scheme)
                    if path!='':
                        path_list.append(path)
            self.output = []
            result_dict = {}

            # dangerous_permissions가 제대로 추출되는지 확인
            dangerous_keywords, dangerous_permission = self.permissions_in_deeplink(file_path, scheme_list)
            #print(f"Dangerous keywords: {dangerous_keywords}")
            #print(f"Dangerous permissions: {dangerous_permission}")
            for activity in search_path:
                package = file_path.split("java_src\\")[1].split("\\resources")[0]
                activity_path = activity.replace(".", os.sep) + ".java"
                base_path = os.getcwd()
                whole_path = os.path.join(base_path, "java_src", package, "sources", activity_path)
                if os.path.exists(whole_path):
                    sources = ExtractContent(whole_path).extract_content()
                    if sources: #딥링크 체크
                        #print(f"Activity sources: {sources}")
                        params = self.extract_lines_with_pattern(sources)
                        deeplink_params.extend(params)
                        #print(f"Extracted deeplink params: {deeplink_params}")
                        for parameter in deeplink_params:
                            #print(f'parameter{parameter}')
                            # 파라미터 변환 확인
                            if 'R.string' in parameter: #string 따로 #네모로 로직을 그리고 필요한 함수들만 추리기
                                #print('rstring')
                                match = re.search(r'R\.string\.([A-Za-z_]+)', parameter)
                                if match:
                                    #print(f"Matched: {match}")
                                    string_key = parameter.split('R.string.')[1]
                                    package = file_path.split("java_src\\")[1].split("\\resources")[0]
                                    xml_file = os.path.join(os.getcwd(), "java_src", package, "resources", "res", "values", "strings.xml")
                                    #print(f"Extracted key: {key}")
                                    #print(f'xml{xml_file}')
                                    real_parameter = self.resolve_string_key(xml_file, string_key) 
                                    #print(f"Resolved string parameter: {real_parameter}")
                                    #원래 파라미터를 지우고 real_parameter
                                    deeplink_params.remove(parameter)
                                    deeplink_params.append(real_parameter)
                            # 변수인 경우 값을 해석
                            elif '"' not in parameter:
                                #print("notstring")
                                real_parameter = self.resolve_variables(whole_path, parameter)
                                if real_parameter:
                                    #print(f"Resolved variable parameter: {real_parameter}")
                                    deeplink_params.remove(parameter)
                                    deeplink_params.append(real_parameter)
                            #else deeplink_pa
                        deeplink_params=list(set(deeplink_params))
                        if deeplink_params:
                            result_dict = {
                                "scheme": scheme_list,
                                "path":path_list,
                                "activity": activity,
                                "deeplink_params": deeplink_params,
                            }
                else:
                    pass
            self.output.append(result_dict)
            #print(f"DeepLinkAnalyzer: {self.output}")
            return self.output
        else:
            pass