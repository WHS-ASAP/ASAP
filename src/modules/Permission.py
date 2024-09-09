import re
import os
from modules.utils import ExtractContent
import xml.etree.ElementTree as ET
#이미 만들어진 도구에서 permission 관련된 부분 보기. #issue 2020 apk deeplink 테스트 해보기

class PermissionAnalyzer:
    def __init__(self):
        self.dangerous_with_webview = {
            "loadURL": "android.permission.WRITE_EXTERNAL_STORAGE",
            "loadURL": "android.permission.READ_PHONE_STATE",
            "loadURL": "android.permission.ACCESS_FINE_LOCATION",
            "loadURL": "android.permission.CALL_PHONE",
            "loadURL": "android.permission.CAMERA",
            "loadURL": "android.permission.READ_CONTACTS",
            "loadURL": "android.permission.READ_EXTERNAL_STORAGE",
            "loadURL": "android.permission.READ_PHONE_STATE",
            "loadURL": "android.permission.RECORD_AUDIO",
            "loadURL": "android.permission.WRITE_CALENDAR",
            "loadURL": "android.permission.WRITE_CONTACTS",
            "loadURL": "android.permission.INTERNET",
            "loadURL": "android.permission.ACCESS_FINE_LOCATION",
            "evaluateJavascript": "android.permission.WRITE_EXTERNAL_STORAGE",
            "evaluateJavascript": "android.permission.READ_PHONE_STATE",
            "evaluateJavascript": "android.permission.READ_EXTERNAL_STORAGE",
            "evaluateJavascript": "android.permission.ACCESS_FINE_LOCATION",
            "evaluateJavascript": "android.permission.CALL_PHONE",
            "evaluateJavascript": "android.permission.CAMERA",
            "evaluateJavascript": "android.permission.READ_CONTACTS",
            "evaluateJavascript": "android.permission.RECORD_AUDIO",
            "evaluateJavascript": "android.permission.WRITE_CONTACTS",

            "setWebViewClient": "android.permission.READ_EXTERNAL_STORAGE",
            "setWebViewClient": "android.permission.READ_PHONE_STATE",
            "setWebViewClient": "android.permission.WRITE_EXTERNAL_STORAGE",
            "setWebViewClient": "android.permission.CALL_PHONE",
            "setWebViewClient": "android.permission.CAMERA",
            "setWebViewClient": "android.permission.READ_CONTACTS",
            "setWebViewClient": "android.permission.RECORD_AUDIO",
            "setWebViewClient": "android.permission.WRITE_CALENDAR",
            "setWebViewClient": "android.permission.WRITE_CONTACTS",
            "setWebViewClient": "android.permission.ACCESS_FINE_LOCATION",
            "open":"android.permission.READ_EXTERNAL_STORAGE"
            
        }

        self.dangerous_with_scheme = {
            "android.permission.READ_CALENDAR": "content://com.android.calendar/time/",
            "android.permission.READ_CALENDAR": "content://com.android.calendar/events/<event_id>",
            "android.permission.WRITE_CALENDAR": "content://com.android.calendar/events/<event_id>",
            "android.permission.READ_CONTACTS":"content://com.android.contacts/data/",
            "android.permission.WRITE_CONTACTS":"content://com.android.contacts/data/",
            "android.permission.RECEIVE_SMS": "android.provider.Telephony.SMS_RECEIVED",
            "android.permission.READ_EXTERNAL_STORAGE":"file:///sdcard/",
            "android.permission.WRITE_EXTERNAL_STORAGE":"file:///sdcard/",
        }

    # 파싱
    def check_same_webview(self, word):
        for keyword, permission in self.dangerous_with_webview.items():
            if keyword in word:
                return word, self.dangerous_with_webview[keyword]
        return None, None

    def permissions_in_app(self, content):
        tree = ET.ElementTree(ET.fromstring(content))
        root = tree.getroot()
        permissions = []

        for perm in root.findall(".//uses-permission"):
            permissions.append(perm.get('{http://schemas.android.com/apk/res/android}name'))

        return permissions

    def run_webview(self, file_path, words):#keyword_list
        if file_path.endswith("AndroidManifest.xml"):
            content = ExtractContent(file_path).extract_content()
            permissions = self.permissions_in_app(content)#permission구하기
            
            dangerous_keywords = []
            dangerous_permissions = []
            
            for word in words:
                keyword, dangerous_permission = self.check_same_webview(word)
                if dangerous_permission and dangerous_permission in permissions:
                    dangerous_keywords.append(keyword)
                    dangerous_permissions.append(dangerous_permission)
                    
            return dangerous_keywords, dangerous_permissions
        
        return [], []

    def run_deeplink(self, file_path):
        if file_path.endswith("AndroidManifest.xml"):
            content = ExtractContent(file_path).extract_content()
            permissions = self.permissions_in_app(content)
            
            dangerous_info = ""
            
            for permission in permissions:
                if permission in self.dangerous_with_scheme.keys():
                    dangerous_keywords = self.dangerous_with_scheme[permission]
                    dangerous_info += f"Permission '{permission}' is present. The payload may contain: {dangerous_keywords}.\n"
                    
                    
            return dangerous_info