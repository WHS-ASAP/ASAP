from ..model import Rule

REF = {
 'sql':'https://developer.android.com/privacy-and-security/risks/sql-injection',
 'provider':'https://developer.android.com/guide/topics/manifest/provider-element',
 'uri':'https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading',
 'bridge':'https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges',
 'links':'https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks',
 'intent':'https://developer.android.com/privacy-and-security/risks/intent-redirection',
 'hardcode':'https://developer.android.com/privacy-and-security/risks/hardcoded-cryptographic-secrets',
 'firebase':'https://firebase.google.com/docs/projects/api-keys',
 'firebase_rules':'https://firebase.google.com/docs/database/security/core-syntax',
 'firebase_paths':'https://firebase.google.com/docs/database/android/read-and-write',
 'firebase_data':'https://firebase.google.com/docs/database/web/structure-data',
 'crypto':'https://developer.android.com/privacy-and-security/cryptography',
 'deprecated':'https://developer.android.com/jetpack/androidx/releases/security',
 'log':'https://developer.android.com/privacy-and-security/risks/log-info-disclosure',
 'android17':'https://developer.android.com/about/versions/17/behavior-changes-17',
 'nsc':'https://developer.android.com/privacy-and-security/security-config',
 'masvs':'https://mas.owasp.org/MASVS/',
}
RULES: dict[str,Rule] = {}

def rule(id: str, category: str, title: str, severity: str, cwe: str, masvs: str,
         description: str, remediation: str, *refs: str) -> None:
    RULES[id] = Rule(id, category, title, severity, cwe, masvs, description, remediation,
                     tuple(REF[r] for r in refs))

rule('SQL001','SQL_Injection','외부 입력이 SQL 문자열로 전달됨','high','CWE-89','MASVS-CODE',
     '동일 lexical method에서 외부 입력과 동적 SQL 표현식의 연결을 관찰합니다. 도달 가능성은 미검증입니다.',
     'SQL 구문은 상수로 유지하고 값은 selectionArgs 또는 bind 인자로 전달하세요. 식별자·정렬식은 별도 허용 목록을 사용하세요.','sql')
rule('SQL002','SQL_Injection','동적 SQL 구성 검토','medium','CWE-89','MASVS-CODE',
     '동적 SQL 인자를 발견했으나 외부 입력 출처를 확인하지 못했습니다.',
     '동적 값의 출처를 검토하고 매개변수화하세요. 파일 내 다른 안전한 쿼리가 이 쿼리까지 보호하지는 않습니다.','sql')
rule('SQL003','SQL_Injection','권한 경계 없는 exported Provider 검토','low','CWE-926','MASVS-PLATFORM',
     'Provider의 선언된 읽기 또는 쓰기 경계가 비어 있습니다. SQL Injection이나 실제 접근 가능성을 확정하지 않습니다.',
     '필요 없는 Provider는 비공개로 설정하고 필요한 읽기·쓰기 작업에는 적절한 권한과 호출자 검증을 적용하세요.','provider','sql')
rule('WV001','WebView','외부 입력의 WebView 로딩 경로','medium','CWE-20','MASVS-PLATFORM',
     '외부 입력이 WebView 로딩 인자로 전달되는 로컬 표현식 흐름입니다.',
     'URI를 구조적으로 파싱하고 scheme 및 host를 정확한 허용 목록으로 검증하세요. 신뢰하지 않는 콘텐츠와 native bridge를 분리하세요.','uri','bridge')
rule('WV002','WebView','JavaScript native bridge 노출 검토','medium','CWE-749','MASVS-PLATFORM',
     'addJavascriptInterface 호출은 검토 지점이며 그 자체로 취약점은 아닙니다.',
     '신뢰된 콘텐츠만 로드하고 최소한의 bridge API만 노출하세요. 모든 프레임에 대한 노출과 콘텐츠 수명주기를 검토하세요.','bridge')
rule('WV003','WebView','file URL의 교차 출처 접근 허용','high','CWE-200','MASVS-PLATFORM',
     'file URL에서 파일 또는 모든 출처 접근을 명시적으로 허용했습니다.',
     'setAllowUniversalAccessFromFileURLs와 setAllowFileAccessFromFileURLs를 false로 유지하고 WebViewAssetLoader 기반 설계를 검토하세요.','uri','bridge')
rule('WV004','WebView','WebView TLS 오류 무시','high','CWE-295','MASVS-NETWORK',
     'SSL 오류 처리 문맥에서 proceed 호출을 관찰했습니다.',
     'TLS 오류에서는 요청을 취소하세요. 인증서 검증을 우회하는 예외를 배포 코드에 두지 마세요.','nsc')
rule('WV005','WebView','WebView 디버깅 활성화','medium','CWE-489','MASVS-PLATFORM',
     '웹 콘텐츠 디버깅의 명시적 true 설정을 관찰했습니다.',
     '배포 빌드에서 디버깅을 비활성화하고 빌드 변형의 실제 실행 조건을 확인하세요.','masvs')
rule('WV006','WebView','혼합 콘텐츠 허용','medium','CWE-319','MASVS-NETWORK',
     'MIXED_CONTENT_ALWAYS_ALLOW 또는 숫자 0 설정입니다.',
     '암호화되지 않은 하위 리소스를 차단하고 HTTPS 콘텐츠만 사용하세요.','nsc','bridge')
rule('WV007','WebView','WebView 파일 접근 활성화 검토','low','CWE-200','MASVS-PLATFORM',
     '파일 접근 허용만으로 데이터 유출을 확정하지 않습니다.',
     '로컬 파일 접근이 필요한지 검토하고 신뢰하지 않는 URL과 파일 접근 기능을 분리하세요.','uri')
rule('WV008','WebView','웹 메시지 출처 제한 검토','medium','CWE-346','MASVS-PLATFORM',
     '웹 메시지 API의 wildcard 출처 또는 대상 설정을 관찰했습니다.',
     '정확한 HTTPS origin을 지정하고 메시지의 출처와 구조를 검증하세요.','bridge')
rule('WV009','WebView','문자열 기반 URI 검증 검토','low','CWE-20','MASVS-PLATFORM',
     'host 또는 URL에 대한 부분 문자열 검사는 구조적 URI 검증을 대체하지 않습니다.',
     'Uri 파싱 결과의 scheme과 host를 정확히 비교하세요. 단순 contains/startsWith/endsWith만으로 신뢰를 결정하지 마세요.','uri')
rule('WV010','WebView','명시적 평문 트래픽 허용 검토','low','CWE-319','MASVS-NETWORK',
     'Manifest 또는 Network Security Config의 허용 설정입니다. 실제 전송 여부와 WebView 적용 조건은 별도 확인합니다.',
     'Network Security Config에서 필요한 도메인으로 범위를 제한하고 가능하면 평문 연결을 제거하세요.','nsc')
rule('DL001','DeepLink','커스텀 스킴 등록 정보','info','CWE-939','MASVS-PLATFORM',
     '커스텀 스킴은 앱의 입력 경계 정보이며 취약점 확정이 아닙니다.',
     '민감한 진입점에는 인증·인가와 입력 검증을 적용하고 적절한 경우 검증된 App Links를 사용하세요.','links')
rule('DL002','DeepLink','웹 링크 autoVerify 설정 누락 검토','low','CWE-939','MASVS-PLATFORM',
     'http/https VIEW+BROWSABLE 필터에 autoVerify=true가 없습니다. 도메인 검증 성공 여부는 확인하지 않습니다.',
     '검증된 App Links를 구성하고 assetlinks.json 및 디바이스 검증 상태를 별도로 확인하세요.','links')
rule('DL003','DeepLink','외부 Intent 전달 경로 검토','medium','CWE-926','MASVS-PLATFORM',
     '외부 Intent 또는 파싱된 외부 입력의 컴포넌트 시작 경로입니다. Android 16+ 기본 보호와 런타임 조건을 고려해야 합니다.',
     '필요한 필드만 새 Intent로 복사하고 대상 컴포넌트·data·권한 플래그를 제한하세요. 검증된 IntentSanitizer 정책을 검토하세요.','intent')
rule('DL004','DeepLink','Intent launch 보호 해제','high','CWE-693','MASVS-PLATFORM',
     'Android 16에서 도입한 removeLaunchSecurityProtection 호출을 관찰했습니다.',
     '보호 해제가 꼭 필요한지 재검토하고 해제 대신 명시적 대상 및 입력 허용 목록을 사용하세요.','intent')
rule('HC001','HardCoded','민감한 이름의 상수 값 검토','medium','CWE-798','MASVS-STORAGE',
     '민감한 식별자에 할당된 문자열입니다. 유효한 자격 증명 여부는 확인하지 않습니다.',
     '서버 자격 증명을 앱 패키지에 넣지 마세요. 실제 비밀인 경우 폐기·회전하고 서버 측 비밀 관리로 이동하세요.','hardcode')
rule('HC002','HardCoded','패키지 내 private key 표시','high','CWE-321','MASVS-CRYPTO',
     'PEM private key 시작 표시를 관찰했습니다. 테스트 키 또는 public key와 구분하여 검토하세요.',
     '개인키를 앱에 포함하지 마세요. 용도에 맞게 Android Keystore에서 생성·보관하고 노출된 실제 키는 회전하세요.','hardcode','crypto')
rule('HC003','HardCoded','비밀 토큰 형식의 상수','high','CWE-798','MASVS-STORAGE',
     '제한된 토큰 형식과 일치합니다. 활성 여부, 권한, 서비스 접근은 검사하지 않습니다.',
     '소유자가 비밀인지 확인하고 실제 토큰이면 회전하세요. 서버용 토큰을 클라이언트에 배포하지 마세요.','hardcode')
rule('HC004','HardCoded','Google/Firebase API 식별 키 검토','info','CWE-200','MASVS-STORAGE',
     'AIza 형식만으로 비밀키 유출을 판단하지 않습니다. Firebase 전용 제한 키와 Gemini 등 비밀 키의 구분이 필요합니다.',
     '콘솔에서 API 및 앱 제한을 검토하세요. Firebase Rules/App Check/IAM은 별도이며 Gemini Developer API 키는 공개하지 마세요.','firebase')
rule('HC005','HardCoded','URL 내 사용자 정보 상수','medium','CWE-798','MASVS-STORAGE',
     'URL userinfo 영역에 자격 증명 형태의 상수가 있습니다.',
     'URL에 자격 증명을 포함하지 말고 실제 비밀인 경우 회전하세요. 로그 및 버전 관리 기록도 검토하세요.','hardcode')
rule('PM001','Permission','배포 앱 디버깅 설정','high','CWE-489','MASVS-RESILIENCE',
     'android:debuggable=true입니다. 입력이 release 병합 Manifest인지 확인해야 합니다.',
     'release 빌드에서 debuggable=false를 보장하고 실제 배포 APK로 재확인하세요.','masvs')
rule('PM002','Permission','권한 없는 exported 컴포넌트 검토','low','CWE-926','MASVS-PLATFORM',
     '외부에 노출된 컴포넌트의 선언상 권한 경계를 관찰합니다. 정상 launcher 노출은 별도 정보로만 기록합니다.',
     '필요한 진입점만 노출하고 민감한 작업에는 호출자 및 인가 검증을 적용하세요.','provider','masvs')
rule('PM003','Permission','약한 사용자 정의 권한 보호 수준','medium','CWE-732','MASVS-PLATFORM',
     '사용자 정의 permission에 normal/dangerous 또는 생략된 보호 수준을 관찰합니다.',
     '동일 서명 앱 간 접근만 필요하면 signature 보호 수준을 고려하고 사용처의 실제 접근 정책을 확인하세요.','masvs')
rule('PM004','Permission','민감 권한 요청 정보','info','CWE-250','MASVS-PRIVACY',
     '선언된 민감 권한 목록입니다. 요청 또는 선언만으로 과도한 권한을 확정하지 않습니다.',
     '기능에 필요한 권한인지 검토하고 가능한 경우 시스템 선택기와 최소 권한 방식을 사용하세요.','masvs','android17')
rule('PM005','Permission','exported 명시 누락 호환성','medium','CWE-693','MASVS-PLATFORM',
     'targetSdk >= 31인 필터 보유 컴포넌트의 exported 명시가 누락됐습니다. 보안 침해가 아닌 설치·병합 호환성 검토입니다.',
     '실제 병합 Manifest에서 외부 노출 여부를 명시하세요.','masvs')
rule('PM006','Permission','Mutable PendingIntent 검토','low','CWE-926','MASVS-PLATFORM',
     'PendingIntent 생성 시 FLAG_MUTABLE을 관찰합니다. 정당한 사용 사례가 있으므로 취약점 확정이 아닙니다.',
     '변경이 필요 없다면 immutable로 설정하고 mutable이 필요하면 대상·필드·사용처를 최소화하세요.','intent','masvs')
rule('PM007','Permission','Android 17 로컬 네트워크 권한 정보','info','CWE-250','MASVS-PRIVACY',
     'ACCESS_LOCAL_NETWORK 선언을 기록하고 API 37 target 조건을 명시합니다.',
     'API 37 이상 대상 앱에서는 런타임 허용 또는 시스템 매개 선택기 경로를 설계하세요. 선언만으로 권한 허용을 판단하지 마세요.','android17')
rule('DS001','Insecure_DataStorage','취약하거나 결정적인 암호 모드 검토','medium','CWE-327','MASVS-CRYPTO',
     'DES/3DES/RC4 또는 AES ECB 계열 명시를 관찰합니다.',
     '위협 모델에 맞는 인증된 암호화(예: AES-GCM)와 안전한 nonce 생성·키 관리를 적용하세요.','crypto')
rule('DS002','Insecure_DataStorage','레거시 digest 사용 검토','low','CWE-328','MASVS-CRYPTO',
     'MD5/SHA-1은 비보안 체크섬 용도일 수 있으므로 사용 문맥 검토가 필요합니다.',
     '보안 무결성 용도에는 적합한 최신 digest 또는 MAC을 사용하고 비밀번호에는 전용 password hashing 설계를 사용하세요.','crypto')
rule('DS003','Insecure_DataStorage','고정 IV/nonce 표현식 검토','medium','CWE-329','MASVS-CRYPTO',
     'IV/nonce 생성 인자에서 상수 또는 새 zero byte 배열을 관찰합니다. 실제 재사용은 미검증입니다.',
     '암호 모드별 nonce/IV 요구사항을 지키고 암호화마다 적절한 고유성 또는 예측 불가능성을 확보하세요.','crypto')
rule('DS004','Insecure_DataStorage','레거시 world-readable/writeable 저장 모드','medium','CWE-732','MASVS-STORAGE',
     '레거시 공개 저장 모드입니다. 최신 Android에서 동작이 제한되거나 예외가 발생할 수 있습니다.',
     '앱 전용 저장소와 명시적 최소 범위 공유 API를 사용하세요. 지원 OS에서 실제 동작을 확인하세요.','masvs')
rule('DS005','Insecure_DataStorage','민감한 값의 preferences 저장 검토','medium','CWE-312','MASVS-STORAGE',
     'preferences/editor 문맥에서 민감한 값의 putString 호출을 관찰합니다. 암호화 래퍼 구현은 미검증입니다.',
     '필요 없는 민감 데이터는 저장하지 말고 민감도에 맞는 암호화와 Android Keystore 기반 키 관리를 적용하세요.','crypto','masvs')
rule('DS006','Insecure_DataStorage','앱 백업 정책 검토','info','CWE-530','MASVS-STORAGE',
     '백업이 허용되거나 기본 설정입니다. 민감 데이터 포함 여부나 기기별 복원 동작을 확정하지 않습니다.',
     '민감 저장소를 fullBackupContent/dataExtractionRules로 제외하고 OS·OEM별 클라우드 및 기기 간 전송 정책을 확인하세요.','masvs')
rule('DS007','Insecure_DataStorage','Deprecated Security-Crypto API 사용','info','CWE-477','MASVS-CRYPTO',
     'Security-Crypto API 사용은 마이그레이션 정보이며 그 자체로 취약점은 아닙니다.',
     '공식 deprecation 안내에 따라 플랫폼 암호 API 및 Android Keystore 직접 사용으로의 마이그레이션을 검토하세요.','deprecated')
rule('DS008','Insecure_DataStorage','암호 키 생성 인자의 상수 검토','medium','CWE-321','MASVS-CRYPTO',
     'SecretKeySpec에서 상수 바이트/문자열에 기반한 키 재료를 관찰합니다.',
     '고정 키를 앱에 배포하지 말고 키 수명주기와 Android Keystore 사용을 설계하세요.','hardcode','crypto')
rule('DS009','Insecure_DataStorage','Firebase Realtime Database 경로','info','CWE-200','MASVS-STORAGE',
     '소스와 설정에서 Realtime Database 호스트, 참조 및 child 경로를 수집합니다. 동적 경로 값은 미확인으로 표시합니다.',
     '각 경로의 데이터 용도와 소유자별 접근 경계를 확인하고 해당 데이터베이스의 Security Rules와 대조하세요.','firebase_paths','firebase_rules')
rule('DS010','Insecure_DataStorage','Firebase Rules의 무조건 읽기 허용','medium','CWE-200','MASVS-STORAGE',
     '제공된 Realtime Database Rules에서 무조건 허용된 .read와 선언된 하위 경로의 상속 범위를 확인합니다.',
     '공개할 데이터 경로만 읽기를 허용하고 사용자 데이터에는 인증·소유권 조건을 적용하세요. 자식의 false로 부모 허용을 취소할 수 없습니다.','firebase_rules')
rule('DS011','Insecure_DataStorage','Firebase Rules의 무조건 쓰기 허용','high','CWE-862','MASVS-STORAGE',
     '제공된 Realtime Database Rules에서 무조건 허용된 .write를 확인합니다. .validate 조건과 실제 배포 상태는 별도 확인이 필요합니다.',
     '쓰기 권한을 인증된 소유자와 필요한 경로로 제한하고 .validate로 데이터 구조를 검증하세요. 부모 경로의 무조건 허용도 제거하세요.','firebase_rules')
rule('DS012','Insecure_DataStorage','Firebase JSON 하위 경로 목록','info','CWE-200','MASVS-STORAGE',
     '제공된 로컬 JSON의 루트와 하위 객체·배열 경로 및 자료형을 순회하여 기록합니다. 저장된 값은 리포트에 포함하지 않습니다.',
     '데이터 구조를 앱의 참조 경로와 대조하고 각 하위 경로에 적절한 접근 규칙을 설정하세요.','firebase_data','firebase_rules')
rule('LG001','Insecure_Logging','민감한 값의 로그 출력 검토','medium','CWE-532','MASVS-STORAGE',
     '실제 로그 인자의 식별자 또는 보간 값에 민감한 이름을 관찰합니다. 단순 문자열 라벨은 제외합니다.',
     '민감한 값을 로그에서 제거하거나 비가역적으로 최소화하세요. debug guard만을 배포 보안 경계로 가정하지 마세요.','log')
rule('LG002','Insecure_Logging','HTTP 헤더·본문 로깅 설정','medium','CWE-532','MASVS-STORAGE',
     'HttpLoggingInterceptor의 HEADERS/BODY 설정은 헤더나 본문의 민감 데이터를 포함할 수 있습니다. 마스킹 호출은 적용 범위만 관찰합니다.',
     '배포 빌드의 헤더·본문 로깅 필요성을 검토하고 토큰·개인정보를 기록하지 마세요. 헤더 마스킹이 본문까지 보호한다고 가정하지 마세요.','log')
