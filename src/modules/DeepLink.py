import xml.etree.ElementTree as ET
from itertools import product

class DeepLinkAnalyzer:
    def __init__(self):
        self.android_ns = 'http://schemas.android.com/apk/res/android'

    def analyze_manifest(self, file_content):
        deeplink_results = []

        try:
            # XML 파싱
            root = ET.fromstring(file_content)
        except ET.ParseError as e:
            print("XML 파싱 에러:", e)
            return deeplink_results

        for intent_filter in root.findall(".//intent-filter"):
            schemes = []
            hosts = []
            ports = []
            all_paths = []

            for data in intent_filter.findall("data"):
                scheme = data.get(f'{{{self.android_ns}}}scheme')
                host = data.get(f'{{{self.android_ns}}}host')
                port = data.get(f'{{{self.android_ns}}}port')
                path = data.get(f'{{{self.android_ns}}}path')
                path_prefix = data.get(f'{{{self.android_ns}}}pathPrefix')
                path_pattern = data.get(f'{{{self.android_ns}}}pathPattern')
                path_advanced_pattern = data.get(f'{{{self.android_ns}}}pathAdvancedPattern')
                path_suffix = data.get(f'{{{self.android_ns}}}pathSuffix')

                if scheme and scheme not in ["http", "https"]:
                    schemes.append(scheme)
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
                all_paths.append('')  # 빈 경로 추가

            for scheme in schemes:
                for host, port, path in product(hosts or [''], ports or [''], all_paths):
                    uri = f"{scheme}://{host}"
                    if port:
                        uri += f":{port}"
                    uri += f"{path}"
                    print("생성된 URI:", uri)  # 디버그 출력
                    deeplink_results.append(uri)

        return deeplink_results

    def run(self, file_content):
        deeplink_results = self.analyze_manifest(file_content)
        if not deeplink_results:
            return None
        return {"manifest": deeplink_results}