import re
import os
from modules.utils import ExtractContent

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
        self.addURI_pattern = re.compile(r'\.addURI\(([^,]+),\s*([^"]+),\s*(\d+)\)', re.IGNORECASE)
        self.uriParse_pattern = re.compile(r'Uri\.parse\("([^"]*)"\)', re.IGNORECASE)
        self.path_pattern1=re.compile(r'("/[^"/>]+")',re.IGNORECASE)

    def searching_activity(self, activities):
        activity_list=[]
        scheme_list=[]
        path_list=[]
        for activity in activities:
            activity_name_pattern = re.compile(r'<activity([^>]+)android:name="([^"]*)"', re.IGNORECASE)
            activity_name = activity_name_pattern.search(activity)
            activity_list.append(activity_name.group(2))
            scheme_match = self.scheme_pattern.findall(activity)
            path_match = self.path_pattern.findall(activity)
            path_match2=self.path_pattern1.findall(activity)

            for scheme in scheme_match:
                scheme_list.append(scheme)
            for path in path_match:
                path_list.append(path)
            for path2 in path_match2:
                path_list.append(path2)
            
            path_list=[]
        return activity_list,scheme_list,path_list

    def extract_lines_with_pattern(self, sources):
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
        
    def resolve_string_key(self, file_path, key):  
        if file_path.endswith("strings.xml"):
            content = ExtractContent(file_path).extract_content()
            string_list = content.split("<string ")
            real_scheme=[]
            for string in string_list:
                if "name=" in string:
                    name = string.split("name=")[1].split('"')[1]
                    if name==key:
                        value = string.split("name=")[1].split(">")[1].split("<")[0]
                        real_scheme.append(value)
                    
            return real_scheme 

        
    def resolve_variables(self, file_path, content):
        if isinstance(content, tuple):
            content = " ".join(content)

        pattern = re.compile(rf'{content}=(.*);')
        file_content = ExtractContent(file_path).extract_content()
        
        if file_content:
            for line in file_content.split("\n"):
                match = pattern.search(line)
                if match:
                    return match.group(1)
        return None

    def run(self, file_path):
        path_list=[]
        deeplink_params=[]
        if file_path.endswith("AndroidManifest.xml"):
            content = ExtractContent(file_path).extract_content()
            activities = self.activity_pattern.findall(content)
            activity_list,scheme_list,path_list = self.searching_activity(activities)
            for scheme in scheme_list:
                scheme=f'{scheme}'
                if "@string/" in scheme:
                    key = scheme.split("@string/")[1]
                    package = file_path.split("java_src\\")[1].split("\\resources")[0]
                    xml_file = os.path.join(os.getcwd(), "java_src", package, "resources", "res", "values", "strings.xml")
                    real_scheme = self.resolve_string_key(xml_file, key)
                    scheme_list.remove(scheme)
                    real_scheme=tuple(real_scheme)
                    scheme_list.append(real_scheme)
            for path in path_list:
                if path!='':
                    path_list.append(path)
            self.output = []
            result_dict = {}
            
            for activity in activity_list:
                package = file_path.split("java_src\\")[1].split("\\resources")[0]
                activity_path = activity.replace(".", os.sep) + ".java"
                base_path = os.getcwd()
                whole_path = os.path.join(base_path, "java_src", package, "sources", activity_path)
                if os.path.exists(whole_path):
                    sources = ExtractContent(whole_path).extract_content()
                    if sources: 
                        params = self.extract_lines_with_pattern(sources)
                        deeplink_params.extend(params)
                        for parameter in deeplink_params:
                            # 파라미터 변환 확인
                            if 'R.string' in parameter:
                                match = re.search(r'R\.string\.([A-Za-z_]+)', parameter)
                                if match:
                                    string_key = parameter.split('R.string.')[1]
                                    package = file_path.split("java_src\\")[1].split("\\resources")[0]
                                    xml_file = os.path.join(os.getcwd(), "java_src", package, "resources", "res", "values", "strings.xml")
                                    real_parameter = self.resolve_string_key(xml_file, string_key) 
                                    deeplink_params.remove(parameter)
                                    deeplink_params.extend(real_parameter)
                            # 변수인 경우 값을 해석
                            elif '"' not in parameter:
                                parameter=parameter.replace(" ","")
                                real_parameter = self.resolve_variables(whole_path, parameter)
                                #파라미터에 띄어쓰기가 있을 경우 제거
                                if real_parameter:
                                    deeplink_params.append(real_parameter)

                        deeplink_params=list(set(deeplink_params))
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
                        self.output.append(result_dict)
                else:
                    pass
            return self.output
        else:
            pass