import re
import os
from modules.utils import ExtractContent
from modules.Permission import PermissionAnalyzer

#출력
# {scheme을 쓰는 activity:
# 그 activity의 scheme:
# 그 activity의 path:
# 그 activity와 연관된 모든 param:
#}

class DeepLinkAnalyzer:
    def __init__(self):
        self.java_dir = "java_src"
        self.activity_pattern = re.compile(r'<activity.*?>.*?</activity>', re.DOTALL)
        self.getQueryParameter_pattern = re.compile(r'getQueryParameter\(([^)]+)\)')
        self.scheme_pattern = re.compile(r'android:scheme="([^"]+)"', re.IGNORECASE)
        self.path_pattern=re.compile(r'android:path([^=]+)="([^"]+)"', re.IGNORECASE)
        self.host_pattern = re.compile(r'host', re.IGNORECASE)
        self.addURI_pattern = re.compile(r'\.addURI\(([^,]+),\s*"([^"]+)",\s*(\d+)\)', re.IGNORECASE)
        self.uriParse_pattern = re.compile(r'Uri\.parse\("([^"]*)"\)', re.IGNORECASE)
        self.path_pattern1=re.compile(r'("/[^"/>]+")',re.IGNORECASE)

    def searching_activity(self, activities):
        activity_list=[]
        scheme_list=[]
        #scheme_list=set(scheme_list)
        path_list=[]
        for activity in activities:
            activity_name_pattern = re.compile(r'<activity([^>]+)android:name="([^"]*)"', re.IGNORECASE)
            activity_name = activity_name_pattern.search(activity)
            activity_list.append(activity_name.group(2))
            #print(f'activity_name {activity_list}')
            scheme_match = self.scheme_pattern.findall(activity)
            path_match = self.path_pattern.findall(activity)
            path_match2=self.path_pattern1.findall(activity)
            """if path_match2:
                print(f'path{path_match2}')"""

            """if activity_name and scheme_match:
                activity_list.extend(activity_name)
                #print(activity_list)"""
            for scheme in scheme_match:
                scheme_list.append(scheme)
                #print(f'scheme{scheme_list}')
            for path in path_match:
                path_list.append(path)
            for path2 in path_match2:
                path_list.append(path2)
                """
                if path2:
                    path_list.append(path2)
                    print(f'path{path_list}')"""
                #results.append((activity_name, scheme_match, path_match))
       
            """name_string = activity_name-
                scheme = scheme_match
                print(scheme)
                path = path_match.group(1) if path_match else ''  # path가 없으면 빈 문자열 추가
                results.append((name_string, scheme, path))  # 항상 세 개의 값 반환"""
            scheme_set=set(scheme_list)
            
            path_list=[]
        #print(f'searching activity result {activity_list, scheme_set, path_list}')
        return activity_list,scheme_list,path_list

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
    
    def permissions_in_deeplink(self,xml_path):
        analyzer = PermissionAnalyzer()
        dangerous_permissions = analyzer.run_deeplink(xml_path)
        return dangerous_permissions
        
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
        path_list=[]
        deeplink_params=[]
        if file_path.endswith("AndroidManifest.xml"):
            #print('in_androidmanifest')
            content = ExtractContent(file_path).extract_content()
            activities = self.activity_pattern.findall(content)
            activity_list,scheme_list,path_list = self.searching_activity(activities)
            #print(f"Activity schemes: {activity_list,scheme_list,path_list}")
            for scheme in scheme_list:
                scheme=f'{scheme}'
                if "@string/" in scheme:
                    #print(f'here! {scheme}')
                    key = scheme.split("@string/")[1]
                    package = file_path.split("java_src\\")[1].split("\\resources")[0]
                    xml_file = os.path.join(os.getcwd(), "java_src", package, "resources", "res", "values", "strings.xml")
                    real_scheme = self.resolve_string_key(xml_file, key)
                    #print(f'new here {real_scheme}')
                    scheme_list.remove(scheme)
                    real_scheme=tuple(real_scheme)
                    print(f'real_scheme{real_scheme}')
                    scheme_list.append(real_scheme)
            for path in path_list:
                if path!='':
                    path_list.append(path)
            self.output = []
            result_dict = {}
            # dangerous_permissions가 제대로 추출되는지 확인
            dangerous_permission = self.permissions_in_deeplink(file_path)
            #print(f"Dangerous keywords: {dangerous_keywords}")
            #print(f"Dangerous permissions: {dangerous_permission}")
            for activity in activity_list:
                #print(f'activity {activity}')
                #activity=f'{activity}'
                package = file_path.split("java_src\\")[1].split("\\resources")[0]
                activity_path = activity.replace(".", os.sep) + ".java"
                base_path = os.getcwd()
                whole_path = os.path.join(base_path, "java_src", package, "sources", activity_path)
                ##print(f'whole_path{whole_path}')
                if os.path.exists(whole_path):
                    #print(f'whole_path {whole_path}')
                    sources = ExtractContent(whole_path).extract_content()
                    if sources: #딥링크 체크
                        #print(sources)
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
                    
                        deeplink_params=list(set(deeplink_params))
                        #scheme_list=tuple(scheme_list)
                        #path_list=tuple(path_list)
                        scheme_list=set(scheme_list)
                        path_list=set(path_list)
                        if deeplink_params:
                            result_dict = {
                                "activity": activity,
                                "scheme": scheme_list,
                                "path":path_list,
                                "deeplink_params": deeplink_params,
                            }
                        else:
                            result_dict = {
                                "activity": activity,
                                "scheme": scheme_list,
                                "path":path_list,
                            }
                        #print(result_dict)
                        self.output.append(result_dict)
                else:
                    pass
            #self.output.append(result_dict)
            #print(result_dict)
            print(f"DeepLinkAnalyzer: {self.output}")
            return self.output
        else:
            pass