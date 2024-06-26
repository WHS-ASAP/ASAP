import xml.etree.ElementTree as ET
import os

# AndroidManifest.xml 파일 경로
path=os.getcwd()
print(path)
manifest_file = 'C:\\Users\\LG\\Desktop\\AAA\\ASAP\\src\\java_src\\com.zellepay.zelle\\resources\\AndroidManifest.xml'

# 악용될 가능성이 높은 권한 리스트
dangerous_permissions = [
    'android.permission.READ_CALENDAR',
    'android.permission.WRITE_CALENDAR',
    'android.permission.CAMERA',
    'android.permission.READ_CONTACTS',
    'android.permission.WRITE_CONTACTS',
    'android.permission.GET_ACCOUNTS',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION',
    'android.permission.RECORD_AUDIO',
    'android.permission.READ_PHONE_STATE',
    'android.permission.CALL_PHONE',
    'android.permission.ADD_VOICEMAIL',
    'android.permission.USE_SIP',
    'android.permission.READ_CALL_LOG',
    'android.permission.WRITE_CALL_LOG',
    'android.permission.SEND_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.READ_SMS',
    'android.permission.RECEIVE_WAP_PUSH',
    'android.permission.RECEIVE_MMS',
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE'
]

def find_dangerous_permissions(manifest_file):
    tree = ET.parse(manifest_file)
    root = tree.getroot()

    found_permissions = []

    # XML namespace
    android_namespace = 'http://schemas.android.com/apk/res/android'
    
    # Iterate through the manifest file to find permissions
    for element in root.iter('uses-permission'):
        permission = element.get(f'{{{android_namespace}}}name')
        if permission in dangerous_permissions:
            found_permissions.append(permission)
    
    return found_permissions

# 불필요한 권한 감지 및 출력
dangerous_permissions_found = find_dangerous_permissions(manifest_file)
if dangerous_permissions_found:
    print("악용될 가능성이 높은 권한이 발견되었습니다:")
    for perm in dangerous_permissions_found:
        print(f"- {perm}")
else:
    print("악용될 가능성이 높은 권한이 없습니다.")
