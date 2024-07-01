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
        try:
            root = ET.fromstring(file_content)
        except ET.ParseError as e:
            return deeplink_results, schemes_deeplink
        
        package_name = root.attrib.get('package', '').strip()

        
        strings_file_path = self.locate_strings_xml(smali_dir, package_name)

        for intent_filter in root.findall(".//intent-filter"):
            schemes = []
            hosts = []
            ports = []
            all_paths = []
            for data in intent_filter.findall("data"):
                scheme = data.get(f'{{{self.android_ns}}}scheme')
                if scheme and scheme.startswith('@string/'):
                    scheme_resource = scheme.split('@string/')[1]
                    if strings_file_path:
                        scheme_value = self.load_strings_xml(strings_file_path, scheme_resource)
                        if scheme_value:
                            scheme = scheme_value
                        else:
                            print(f"Warning: String resource '{scheme_resource}' not found in strings.xml")
                host = data.get(f'{{{self.android_ns}}}host')
                port = data.get(f'{{{self.android_ns}}}port')
                path = data.get(f'{{{self.android_ns}}}path')
                path_prefix = data.get(f'{{{self.android_ns}}}pathPrefix')
                path_pattern = data.get(f'{{{self.android_ns}}}pathPattern')
                path_advanced_pattern = data.get(f'{{{self.android_ns}}}pathAdvancedPattern')
                path_suffix = data.get(f'{{{self.android_ns}}}pathSuffix')
                if scheme and scheme not in ["http", "https"]:
                    schemes.append(scheme)
                    schemes_deeplink.add(scheme)
                if host:
                    hosts.append(host)
                if port:
                    ports.append(port)
                if path:
                    all_paths.append(path)
                if path_prefix:
                    all_paths.append(path_prefix)
                if path_pattern:
                    all_paths.append(path_pattern)
                if path_advanced_pattern:
                    all_paths.append(path_advanced_pattern)
                if path_suffix:
                    all_paths.append(path_suffix)

            if not all_paths:
                all_paths.append('')
            for scheme in schemes:
                for host, port, path in product(hosts or [''], ports or [''], all_paths):
                    uri = f"{scheme}://{host}"
                    if port:
                        uri += f":{port}"
                    uri += f"{path}"
                    deeplink_results.add(uri)

        return list(deeplink_results),  schemes_deeplink

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
        file_path = os.path.normpath(file_path)
        try:
            with open(file_path, encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return [], [], [], [], []

        local_register = {}
        param = set()
        addURI = set()
        UriParse = set()
        addJsIf = set()
        method = set()
        for line in lines:
            line = line.strip()
            if not line:
                continue

            words = line.split()
            if words[0] == ".class":
                class_name = line
            elif words[0] == ".method":
                method_name = line

            if ".annotation" in line and "Landroid/webkit/JavascriptInterface" in line:
                method.add(method_name.split()[2].split("(")[0])

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

    def parse_smali_directory(self, directory, manifest_schemes):
        params = set()
        addURIs = set()
        UriParses = set()
        tmpUriParse = set()
        addJsIf = set()
        methods = set()

        def process_file(file_path):
            return self.parse_smali_file(file_path)

        with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            futures = []
            for path, dirs, files in os.walk(directory):
                for file in files:
                    if file.endswith(".smali"):
                        file_path = os.path.join(path, file)
                        futures.append(executor.submit(process_file, file_path))

            for future in as_completed(futures):
                param, addURI, UriParse, addJsIf_list, method = future.result()
                if param:
                    params.update(param)
                if addURI:
                    addURIs.update(addURI)
                if UriParse:
                    tmpUriParse.update(UriParse)
                if addJsIf_list:
                    addJsIf.update(addJsIf_list)
                if method:
                    methods.update(method)

        for uri in tmpUriParse:
            for scheme in manifest_schemes:
                if uri.startswith(scheme):
                    UriParses.add(uri)
                    break

        return {
            "params": list(params),
            "addURIs": list(addURIs),
            "addJsIf": list(addJsIf),
            "UriParses": list(UriParses),
            "method": list(methods),
        }





    def run(self, manifest_content, smali_dir):
        try:
            deeplink_results, manifest_schemes = self.analyze_manifest(manifest_content, smali_dir)
        except Exception as e:
            print(f"Error analyzing manifest: {e}")
            deeplink_results, manifest_schemes = [], set()

        try:
            smali_results = self.parse_smali_directory(smali_dir, manifest_schemes)
        except Exception as e:
            print(f"Error analyzing smali directory: {e}")
            smali_results = {}

        formatted_results = {
            "manifest": [f"{item}" for item in deeplink_results],
            "Scheme UriParses": [f"{item}" for item in smali_results.get("UriParses", [])],
            "host, path": [f"{item}" for item in smali_results.get("addURIs", [])],
            "params": [f"{item}" for item in smali_results.get("params", [])],
            "JavascriptInterface method": [f"{item}" for item in smali_results.get("method", [])],
            "addJavascriptInterface": [f"{item}" for item in smali_results.get("addJsIf", [])],
        }

        return formatted_results