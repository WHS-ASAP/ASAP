import re

class DeepLinkAnalyzer:
    def __init__(self):
        self.uri_scheme_pattern = re.compile(r'<data android:scheme="(\w+)"')
        self.host_pattern = re.compile(r'<data android:host="([^"]+)"')
        self.intent_filter_pattern = re.compile(r'<intent-filter>(.*?)</intent-filter>', re.DOTALL)

    def analyze_manifest(self, file_content):
        uri_schemes = self.uri_scheme_pattern.findall(file_content)
        hosts = self.host_pattern.findall(file_content)
        intent_filters = self.intent_filter_pattern.findall(file_content)
        if not uri_schemes and not hosts and not intent_filters:
            return None
        return {"uri_schemes": uri_schemes, "hosts": hosts, "intent_filters": intent_filters}

    def run(self, file_content):
        manifest_results = self.analyze_manifest(file_content)
        if not manifest_results:
            return None
        return {"manifest": manifest_results}
