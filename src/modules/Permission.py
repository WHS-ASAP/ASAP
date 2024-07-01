import xml.etree.ElementTree as ET
import os


class PermissionAnalyzer:
    def __init__(self):
        self.dangerous_Permissions = [
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.GET_ACCOUNTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CALL_PHONE",
            "android.permission.ADD_VOICEMAIL",
            "android.permission.USE_SIP",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_WAP_PUSH",
            "android.permission.RECEIVE_MMS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        ]

    # 파싱
    def permissions_in_app(self, content):
        tree = ET.ElementTree(
            ET.fromstring(content)
        )  # ET -> ElementTree모듈, manifest_file 경로에서 XML 파일 파싱해서 트리 구조로 만든다. 이를 tree에 저장.
        root =tree.getroot() # tree 변수에서 최상위(root)엘리먼트를 얻어 옴. 최상위 엘리먼트는 XML 문서의 가장 바깥쪽 요소를 의미
        permissions = []  # 파싱한 permission들 저장할 리스트

        for perm in root.findall(".//uses-permission"):  # perm이라는 가상 for문 변수 생성 -> root에서 저기에 해당하는 permission들 찾기
            permissions.append(perm.get('{http://schemas.android.com/apk/res/android}name'))  # android:name 속성의 값을 추출한다.

        return permissions  # 파싱된 permission리스트 반환

    def check_same(self, content):
        
        dangerous_in_app = []

        # perm -> permissions_in_app리스트의 각 요소를 하나씩 의미.
        for perm in self.permissions_in_app(content):  # 클래스 내부에서 변수나 메소드 참조할 때 self. 사용->self가 매개변수로 전달되어 해당 객체의 속성이나 기능에 접근 가능하다
            if (
                perm in self.dangerous_Permissions
            ):  # perm이 dangerous_Permissions에 만약에 있다면?
                dangerous_in_app.append(perm)  # dangerous_in_app 리스트에 perm 추가

        return dangerous_in_app

    def run(self, content):
        dangerous_in_app = self.check_same(content)
        if dangerous_in_app:  # 만약 dangerous_in_app리스트가 채워져있으면?
            return dangerous_in_app  # 해당 리스트 내용 출력
        