import re

class PermissionAnalyzer:
    def __init__(self):
        self.dangerous_permissions = [
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

        self.permission_pattern = re.compile(
            r'<uses-permission\s+android:name="(android\.permission\.[A-Z_]+)"', re.IGNORECASE)

    def run(self, file_content):
        results = []
        matches = self.permission_pattern.finditer(file_content)
        for match in matches:
            permission = match.group(1)
            if permission in self.dangerous_permissions:
                results.append(f'Found dangerous permission: {permission}')
        return results if results else None


if __name__ == "__main__":
    pass
