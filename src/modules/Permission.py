import re
import os
from modules.utils import ExtractContent
import xml.etree.ElementTree as ET

class PermissionAnalyzer:
    def __init__(self):
        self.dangerous_with_jsmethod = {
            "open":"android.permission.READ_EXTERNAL_STORAGE",
            "read":"android.permission.READ_EXTERNAL_STORAGE",
            "write":"android.permission.WRITE_EXTERNAL_STORAGE",
            "delete":"android.permission.WRITE_EXTERNAL_STORAGE",            
        }

        self.dangerous_with_scheme = {
            "android.permission.READ_CALENDAR": "content://com.android.calendar/time/",
            "android.permission.READ_CALENDAR": "content://com.android.calendar/events/<event_id>",
            "android.permission.WRITE_CALENDAR": "content://com.android.calendar/events/<event_id>",
            "android.permission.READ_CONTACTS":"content://com.android.contacts/data/",
            "android.permission.WRITE_CONTACTS":"content://com.android.contacts/data/",
            "android.permission.READ_EXTERNAL_STORAGE":"file:///sdcard/",
            "android.permission.WRITE_EXTERNAL_STORAGE":"file:///sdcard/",
        }

    def check_same_jsmethod(self, word):
        for keyword, permission in self.dangerous_with_jsmethod.items():
            if keyword in word:
                return word, self.dangerous_with_jsmethod[keyword]
        return None, None

    def permissions_in_app(self, content):
        tree = ET.ElementTree(ET.fromstring(content))
        root = tree.getroot()
        permissions = []

        for perm in root.findall(".//uses-permission"):
            permissions.append(perm.get('{http://schemas.android.com/apk/res/android}name'))

        return permissions

    def run_jsmethod(self, file_path, words):
        if file_path.endswith("AndroidManifest.xml"):
            content = ExtractContent(file_path).extract_content()
            permissions = self.permissions_in_app(content)
            
            dangerous_keywords = []
            dangerous_permissions = []
            
            for word in words:
                keyword, dangerous_permission = self.check_same_jsmethod(word)
                if dangerous_permission and dangerous_permission in permissions:
                    dangerous_keywords.append(keyword)
                    dangerous_permissions.append(dangerous_permission)
                    
            return dangerous_keywords, dangerous_permissions
        
        return [], []

    def run(self, file_path):
        if file_path.endswith("AndroidManifest.xml"):
            content = ExtractContent(file_path).extract_content()
            permissions = self.permissions_in_app(content)
            
            dangerous_info = ""
            
            for permission in permissions:
                if permission in self.dangerous_with_scheme.keys():
                    dangerous_keywords = self.dangerous_with_scheme[permission]
                    dangerous_info += f"Permission '{permission}' is present. The payload may contain: {dangerous_keywords}.\n"
                    
            return dangerous_info