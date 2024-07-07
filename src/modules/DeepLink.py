import os
import xml.etree.ElementTree as ET
from itertools import product
from concurrent.futures import ThreadPoolExecutor, as_completed

class DeepLinkAnalyzer:
    def __init__(self):
        self.android_ns = 'http://schemas.android.com/apk/res/android'

    def analyze_manifest(self, file_content, smali_dir):
        deeplink_results = set()
        schemes_deeplink = set()
        activity_schemes = {}

        try:
            root = ET.fromstring(file_content)
        except ET.ParseError as e:
            return deeplink_results, schemes_deeplink, activity_schemes

        package_name = root.attrib.get('package', '').strip()
        strings_file_path = self.locate_strings_xml(smali_dir, package_name)

        for activity in root.findall(".//activity"):
            activity_name = activity.attrib.get(f'{{{self.android_ns}}}name')
            if not activity_name:
                continue  # activity_name이 없으면 무시
            activity_uri_list = []
            for intent_filter in activity.findall("intent-filter"):
                schemes, hosts, ports, all_paths = [], [], [], []
                for data in intent_filter.findall("data"):
                    scheme = self.resolve_scheme(data.get(f'{{{self.android_ns}}}scheme'), strings_file_path)
                    host = self.resolve_host(data.get(f'{{{self.android_ns}}}host'), strings_file_path)
                    port = data.get(f'{{{self.android_ns}}}port')
                    paths = [
                        self.resolve_path(data.get(f'{{{self.android_ns}}}path'), strings_file_path),
                        self.resolve_path(data.get(f'{{{self.android_ns}}}pathPrefix'), strings_file_path),
                        self.resolve_path(data.get(f'{{{self.android_ns}}}pathPattern'), strings_file_path),
                        self.resolve_path(data.get(f'{{{self.android_ns}}}pathAdvancedPattern'), strings_file_path),
                        self.resolve_path(data.get(f'{{{self.android_ns}}}pathSuffix'), strings_file_path),
                    ]
                    if scheme and scheme not in ["http", "https"]:
                        schemes.append(scheme)
                        schemes_deeplink.add(scheme)
                    if host:
                        hosts.append(host)
                    if port:
                        ports.append(port)
                    all_paths.extend(filter(None, paths))

                if not all_paths:
                    all_paths.append('')
                for scheme in schemes:
                    for host, port, path in product(hosts or [''], ports or [''], all_paths):
                        uri = f"{scheme}://{host}"
                        if port:
                            uri += f":{port}"
                        if path:
                            uri += f"{path}"
                        deeplink_results.add(uri)
                        activity_uri_list.append(uri)

            if activity_uri_list:
                if activity_name not in activity_schemes:
                    activity_schemes[activity_name] = []
                activity_schemes[activity_name].extend(activity_uri_list)

        # Combine all URIs for each activity into a single string
        combined_activity_schemes = {
            activity: " , ".join(uris)
            for activity, uris in activity_schemes.items()
        }

        return schemes_deeplink, combined_activity_schemes

    def resolve_scheme(self, scheme, strings_file_path):
        if scheme and scheme.startswith('@string/') and strings_file_path:
            scheme_resource = scheme.split('@string/')[1]
            scheme_value = self.load_strings_xml(strings_file_path, scheme_resource)
            if scheme_value:
                return scheme_value
            print(f"Warning: String resource '{scheme_resource}' not found in strings.xml")
        return scheme
    
    def resolve_host(self, host, strings_file_path):
        if host and host.startswith('@string/') and strings_file_path:
            host_resource = host.split('@string/')[1]
            host_value = self.load_strings_xml(strings_file_path, host_resource)
            if host_value:
                return host_value
            print(f"Warning: String resource '{host_resource}' not found in strings.xml")
        return host
    
    def resolve_path(self, path, strings_file_path):
        if path and path.startswith('@string/') and strings_file_path:
            path_resource = path.split('@string/')[1]
            path_value = self.load_strings_xml(strings_file_path, path_resource)
            if path_value:
                return path_value
            print(f"Warning: String resource '{path_resource}' not found in strings.xml")
        return path
    
    def locate_strings_xml(self, smali_dir, package_name):
        values_dir = os.path.join(smali_dir, package_name, 'res', 'values')
        strings_file_path = os.path.join(values_dir, 'strings.xml')
        
        if os.path.exists(strings_file_path):
            return strings_file_path
        else:
            print(f"Warning: strings.xml file not found in {values_dir}")
            return None
        
    def load_strings_xml(self, strings_file_path, scheme_resource):
        try:
            tree = ET.parse(strings_file_path)
            root = tree.getroot()
            for string_element in root.findall('string'):
                name = string_element.attrib['name']
                if name == scheme_resource:
                    return string_element.text.strip()
        except ET.ParseError as e:
            print(f"Error parsing strings.xml: {e}")
    
    def parse_smali_file(self, file_path):
        try:
            with open(file_path, encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return [], [], [], [], []

        local_register = {}
        param, addURI, UriParse, addJsIf, method = set(), set(), set(), set(), set()

        for line in lines:
            line = line.strip()
            if not line:
                continue

            words = line.split()
            if words[0] == ".class" :
                class_name = line
            elif words[0] == ".method" :
                method_name = line 
            
            if ".annotation" in line and "Landroid/webkit/JavascriptInterface" in line:
                method.add(method_name.split(" ")[2].split("(")[0])

            try:
                if "const-string" in line:
                    local_register[words[1][:-1]] = words[2].split("\"")[1]
                elif "getQueryParameter(" in line:
                    if "}" not in line:
                        continue
                    var = line.split("}")[0].split()[-1]
                    if var in local_register:
                        param.add(local_register[var])
                elif "addURI(" in line:
                    var_list = line.split("{")[1].split("}")[0].split(", ")
                    if var_list[1] in local_register and var_list[2] in local_register:
                        host = local_register[var_list[1]]
                        path = local_register[var_list[2]]
                        addURI.add(host + "/" + path)
                elif "Uri;->parse(" in line:
                    var = line.split("{")[1].split("}")[0]
                    if var in local_register:
                        UriParse.add(local_register[var])
                elif "addJavascriptInterface(" in line:
                    if "}" not in line: continue

                    var_list = line.split("{")[1].split("}")[0].split(", ")
                    if var_list[1] in local_register and var_list[2] in local_register:
                        addJsIf.add(local_register[var_list[2]])

                


            except Exception as e:
                print(f"Error processing line in {file_path}: {e}")
                continue

        return list(param), list(addURI), list(UriParse), list(addJsIf), list(method)
    
    def extract_var(self, line):
        return line.split("}")[0].split()[-1]

    def extract_vars(self, line):
        return line.split("{")[1].split("}")[0].split(", ")
    
    def parse_smali_directory(self, directory, manifest_schemes):
        params, addURIs, UriParses, tmpUriParse, addJsIfs, methods = set(), set(), set(), set(), set(), set()

        with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            futures = [
                executor.submit(self.parse_smali_file, os.path.join(path, file))
                for path, _, files in os.walk(directory)
                for file in files if file.endswith(".smali")
            ]

            for future in as_completed(futures):
                param, addURI, UriParse,addJsIf,method = future.result()
                params.update(param)
                addURIs.update(addURI)
                tmpUriParse.update(UriParse)
                addJsIfs.update(addJsIf)
                methods.update(method)

        for uri in tmpUriParse:
            if any(uri.startswith(scheme) for scheme in manifest_schemes):
                UriParses.add(uri)

        return {
            "params": list(params),
            "addURIs": list(addURIs),
            "UriParses": list(UriParses),
            "methods" : list(methods),
            "addJsIfs" : list(addJsIfs)
        }

    def run(self, manifest_content, smali_dir):
        try:
            manifest_schemes, activity_schemes = self.analyze_manifest(manifest_content, smali_dir)
        except Exception as e:
            print(f"Error analyzing manifest: {e}")
            manifest_schemes, activity_schemes = set(), {}

        if not activity_schemes or not manifest_schemes:
            return
        else:
            try:
                smali_results = self.parse_smali_directory(smali_dir, manifest_schemes)
            except Exception as e:
                print(f"Error analyzing smali directory: {e}")
                smali_results = {}

        formatted_results = {}

        if activity_schemes:
            formatted_results["scheme"] = [f"{activity} = {uris}" for activity, uris in activity_schemes.items()]
            
        if smali_results.get("UriParses"):
            formatted_results["UriParses"] = [f"{item}" for item in smali_results["UriParses"]]

        if smali_results.get("params"):
            formatted_results["addable params"] = [f"{item}" for item in smali_results["params"]]

        if smali_results.get("addURIs"):
            formatted_results["addable host, path"] = [f"{item}" for item in smali_results["addURIs"]]

        if smali_results.get("methods"):
            formatted_results["JavascriptInterface Annotation methods"] = [f"{item}" for item in smali_results["methods"]]
        
        if smali_results.get("addJsIfs"):
            formatted_results["addJavascriptInterface"] = [f"{item}" for item in smali_results["addJsIfs"]]



        return formatted_results
