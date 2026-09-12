# ASAP

[English](README.md) · 한국어

ASAP는 보안 분석가와 앱 개발자를 위한 오픈소스 Android 정적 분석 도구입니다. APK 또는 소스 코드를 분석하고, 7개 모듈의 결과를 검토하며, APK마다 워크스페이스를 만들어 관리할 수 있습니다.

## 기능

- APK, APKS, XAPK 및 소스 디렉터리 분석
- 분석 이력, 이름, 메모, 보관, 재분석을 지원하는 APK별 워크스페이스
- 7개 분석 모듈, 43개 규칙과 모듈별 검토 가이드
- 파일 위치, 코드 근거, 심각도, 검토 메모를 제공하는 검색 가능한 결과
- HTML, JSON, SARIF 리포트와 기준선·CI 임계치 설정
- 로컬 CLI와 브라우저 인터페이스

## 시작하기

**Python 3.11 이상**을 사용합니다. APK의 DEX 코드를 분석하려면 JADX를 설치하세요. Apktool은 선택적으로 사용할 수 있습니다. Java 요구사항과 도구 경로 설정은 [도구 설치 안내](docs/toolchain.md)를 참고하세요.

```bash
git clone --branch v3 https://github.com/WHS-ASAP/ASAP.git
cd ASAP
python3 -m asap doctor
python3 -m asap web --workspace .asap-workspace --port 8765
```

브라우저에서 [http://127.0.0.1:8765](http://127.0.0.1:8765)를 열고 APK를 업로드합니다. 서버는 터미널에서 `Ctrl+C`로 종료합니다. Windows에서는 `python3` 대신 `py -3` 또는 `python`을 사용하세요.

도구 경로를 직접 지정하려면 [config.tools.example.json](examples/config.tools.example.json)을 복사하고 `jadx`, `apktool` 경로를 수정한 뒤 실행할 때 전달합니다.

```bash
python3 -m asap web --config my-config.json
```

## APK 워크스페이스

업로드한 APK마다 메타데이터, 분석 이력, 모듈별 결과를 담는 워크스페이스가 생성됩니다. 같은 파일을 다시 업로드하면 같은 공간에 분석 이력이 추가됩니다. 파일 내용이 다르면 패키지명이 같은 빌드라도 별도 공간에서 관리합니다.

워크스페이스에 이름과 메모를 저장하고, 재분석하거나 목록에서 보관할 수 있습니다. 모듈을 열면 분석 결과와 검토 가이드가 표시되며, 각 결과에서 코드 근거를 확인할 수 있습니다. 보관한 워크스페이스는 복원할 수 있습니다.

워크스페이스 정보는 로컬에 저장됩니다. 항목별 검토 상태와 메모는 브라우저에 저장되며, 검토 JSON을 내보내고 가져와 다른 브라우저에서 이어갈 수 있습니다. 자세한 내용은 [워크스페이스 안내](docs/workspaces.md)를 참고하세요.

## 분석 모듈

기본 설정에서는 7개 모듈을 한 번에 분석합니다. 각 카테고리를 펼치면 세부 검사 항목을 확인할 수 있습니다.

<details>
<summary>SQL_Injection · 3개 규칙</summary>

| 규칙 | 검사 항목 |
|---|---|
| `SQL001` | 외부 입력과 연결된 동적 SQL 문자열 |
| `SQL002` | 상수로 확인되지 않은 SQL 인자와 쿼리 구성 |
| `SQL003` | 외부 공개 Content Provider의 읽기·쓰기 권한 경계 |

</details>

<details>
<summary>WebView · 10개 규칙</summary>

| 규칙 | 검사 항목 |
|---|---|
| `WV001` | 외부 입력에서 WebView 로딩 API로 이어지는 경로 |
| `WV002` | addJavascriptInterface를 통한 JavaScript 브리지 노출 |
| `WV003` | file URL의 파일 간·출처 간 접근 허용 설정 |
| `WV004` | TLS 오류 처리에서 요청을 계속하는 proceed 호출 |
| `WV005` | WebView 콘텐츠 디버깅 활성화 설정 |
| `WV006` | 암호화되지 않은 혼합 콘텐츠 허용 설정 |
| `WV007` | WebView의 로컬 파일 접근 활성화 설정 |
| `WV008` | 웹 메시지 API의 와일드카드 출처·대상 설정 |
| `WV009` | URL·호스트의 부분 문자열에 의존하는 URI 검증 |
| `WV010` | Manifest·Network Security Config의 평문 트래픽 허용 설정 |

</details>

<details>
<summary>DeepLink · 4개 규칙</summary>

| 규칙 | 검사 항목 |
|---|---|
| `DL001` | Manifest에 등록된 커스텀 URI 스킴 |
| `DL002` | 웹 링크 intent-filter의 autoVerify 설정 누락 |
| `DL003` | 외부 Intent 또는 파싱한 외부 입력의 컴포넌트 전달 경로 |
| `DL004` | Intent의 removeLaunchSecurityProtection 호출 |

</details>

<details>
<summary>HardCoded · 5개 규칙</summary>

| 규칙 | 검사 항목 |
|---|---|
| `HC001` | 민감한 이름의 식별자에 할당된 문자열 상수 |
| `HC002` | 패키지에 포함된 PEM 개인 키 표시 |
| `HC003` | 자격 증명·비밀 토큰 형식과 일치하는 상수 |
| `HC004` | Google API 키 형식과 같은 파일의 서비스 사용 단서 |
| `HC005` | URL 사용자 정보 영역에 포함된 자격 증명 형태의 상수 |

</details>

<details>
<summary>Permission · 7개 규칙</summary>

| 규칙 | 검사 항목 |
|---|---|
| `PM001` | Manifest의 앱 디버깅 활성화 설정 |
| `PM002` | 선언된 권한 경계가 없는 외부 공개 컴포넌트 |
| `PM003` | 사용자 정의 권한의 normal·dangerous 또는 생략된 보호 수준 |
| `PM004` | 민감 권한 선언과 SDK 적용 범위 |
| `PM005` | targetSdk 31 이상에서 intent-filter를 가진 컴포넌트의 exported 명시 누락 |
| `PM006` | PendingIntent의 FLAG_MUTABLE 설정 |
| `PM007` | ACCESS_LOCAL_NETWORK 선언과 API 37 대상 조건 |

</details>

<details>
<summary>Insecure_DataStorage · 12개 규칙</summary>

| 규칙 | 검사 항목 |
|---|---|
| `DS001` | DES·3DES·RC4 및 AES ECB 계열 암호 모드 |
| `DS002` | MD5·SHA-1 등 레거시 해시 사용 |
| `DS003` | IV·nonce 생성에 사용된 상수 또는 고정 바이트 배열 |
| `DS004` | 레거시 world-readable·world-writeable 저장 모드 |
| `DS005` | 민감한 값의 Preferences 저장 표현식 |
| `DS006` | 앱 백업 설정과 백업 규칙 참조 |
| `DS007` | 더 이상 권장되지 않는 AndroidX Security-Crypto API 사용 |
| `DS008` | SecretKeySpec의 상수 기반 암호 키 재료 |
| `DS009` | 소스·설정의 Firebase 데이터베이스 호스트와 getReference·child 참조 경로 |
| `DS010` | 제공된 Firebase Rules의 무조건 읽기 허용과 하위 경로 상속 |
| `DS011` | 제공된 Firebase Rules의 무조건 쓰기 허용과 하위 경로 상속 |
| `DS012` | 제공된 로컬 Firebase JSON의 루트·하위 객체·배열 경로와 자료형 |

</details>

<details>
<summary>Insecure_Logging · 2개 규칙</summary>

| 규칙 | 검사 항목 |
|---|---|
| `LG001` | 로그 인자·문자열 보간에 포함된 민감한 값의 식별자 |
| `LG002` | HttpLoggingInterceptor의 HEADERS·BODY 로깅 설정 |

</details>

각 규칙의 적용 조건과 권장 조치는 [규칙 카탈로그](docs/rule-catalog.md)에서 확인할 수 있습니다. 규칙 목록은 `python3 -m asap rules`로도 볼 수 있습니다.

## CLI

```bash
# PATH에 등록된 도구로 APK 분석
python3 -m asap scan ./sample.apk -o results/sample

# 디컴파일러 경로 직접 지정
python3 -m asap scan ./sample.apk -o results/sample \
  --jadx /absolute/path/jadx/bin/jadx \
  --apktool /absolute/path/apktool.jar

# 소스 코드 또는 JADX 출력 디렉터리 분석
python3 -m asap scan ./decompiled-app -o results/source

# APKS 또는 XAPK 아카이브 분석
python3 -m asap scan ./sample.apks -o results/splits

# 원하는 모듈만 분석
python3 -m asap scan ./decompiled-app -o results/selected \
  --categories WebView,DeepLink

# 포함된 샘플 소스 분석
python3 -m asap scan tests/fixtures/demo -o results/demo
```

설정 파일에서 모듈, 제외 경로, 처리 한도, 도구 경로, 결과 제외 조건을 지정할 수 있습니다. [config.example.json](examples/config.example.json)을 참고하고 `--config my-config.json`으로 전달하세요. 디컴파일러를 호출하지 않고 읽을 수 있는 XML과 자산만 검사하려면 `--no-decompile`을 사용합니다. 이 경우 DEX 분석 범위는 미완료로 표시됩니다.

## 리포트

분석마다 출력 디렉터리에 다음 파일이 생성됩니다.

| 파일 | 용도 |
|---|---|
| `report.html` | 브라우저에서 결과, 코드 근거, 모듈 가이드, 검토 메모 확인 |
| `report.json` | 구조화된 분석 결과와 분석 범위 정보 |
| `report.sarif` | 개발 도구 연동을 위한 SARIF 2.1.0 결과 |

`--legacy-json`을 지정하면 `legacy_findings.json`도 생성합니다. HTML 리포트에서는 모듈, 심각도, 검토 상태, 텍스트로 결과를 필터링하고 검토 기록을 내보내거나 가져올 수 있습니다.

## 기준선과 CI

```bash
python3 -m asap baseline results/sample/report.json -o baseline.json
python3 -m asap scan ./sample.apk -o results/next \
  --baseline baseline.json --only-new --fail-on high --strict
python3 -m asap diff results/sample/report.json results/next/report.json
```

`--fail-on`은 심각도 임계치를 설정하고, `--only-new`는 기준선에 없는 결과에만 임계치를 적용합니다. `--strict`는 분석 범위 진단이 있으면 실패로 처리합니다. 종료 코드는 임계치 미만으로 완료하면 `0`, 임계치에 도달하면 `1`, 오류나 strict 분석 범위 진단은 `2`, 사용자 중단은 `130`입니다.

## 문서

[워크스페이스](docs/workspaces.md) · [도구 설치](docs/toolchain.md) · [규칙](docs/rule-catalog.md) · [구조](docs/architecture.md) · [테스트](docs/testing.md) · [보안](docs/security.md)

## Contributor version 3.0

- Jeongahn Jang ([@jh4nks](https://github.com/jh4nks))

## 라이선스

[MIT](LICENSE)

## v1 / v2 기록

이전 버전의 사용 안내와 기여자 기록입니다. 해당 소스는 [main 브랜치](https://github.com/WHS-ASAP/ASAP/tree/main)에서 확인할 수 있습니다.

<details>
<summary>v1 / v2 — 원본 도구 소개·사용 안내</summary>

# ASAP
This WhiteHat School(WHS) Project is an *open-source*, analysis tool to support for App Vulnerability Manual Analysis Hackers and App Developers.  

The ASAP tool basically provides possible locations for vulnerabilities in code obtained using the jadx decompiler. 

ASAP only supports static analysis. 


---
Scope of Vulnerabilities in ASAP: 
   + SQL_Injection
     > Detects query statements, detects the uri address of Content Provider with exported = true, and returns it to the result value
   + WebView
     > Detect if you use an external intent as an activity target with [exported="true"] exported from androidmanifest.xml and load the intent with loadURL => webview vulnerability detection
Check presence of function that allows file access with javascripted function in same activity => xss vulnerability detection
   + DeepLink
     > Print [scheme://host/path] from Androidmanifest.xml, detection of parameters through getQueryParameter function in smali code, adjustable host/path through addURI function, url matching scheme through 'Uri; ->parse, JavascriptInterface Detection of JavascriptInterface Available in WebView via JavascriptInterface Annotation, addJavascriptInterface Detection =>Redirect Vulnerability
   + HardCoded
     > API Key or Credentials inside the apk
   + Permission
     > Extract Permission from Android Manifest in xml Code
   + Insecure_DataStorage (Crypto)
     > Extract encryption logic within Shared Preference
   + Insecure_Logging (LogE)
     > Log detection that outputs sensitive information in Java code
---



## ASAP Tool Guide
### 1. Getting Started

```
git clone https://github.com/WHS-ASAP/ASAP.git
cd ASAP
pip install -r requirements.txt
```
---
### 2. Add ASAP/src/tools/jadx/lib/jadx-dev-all.jar

<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/242397f6-c92a-4900-962c-f4ef7e854b45" width="100%" height="100%">
</p>
Download the jadx-dev-all.jar file from here: https://drive.google.com/file/d/1u2BQv8YsoNmeNCLvpt2V9HRhnzU-51Q8/view?usp=sharing

---


### 3. If you want to set target applications, go to ASAP/src/docs/target.txt and write app package name

<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/24f76541-f2f5-4d1d-9356-1ea324c7c614" width="100%" height="100%">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/9c5db5d1-6c0c-4267-a876-98d1df9c86c1" width="30%" height="30%"> <br>
   <a href="https://github.com/WHS-ASAP/ASAP/blob/readme/src/docs/Readme.md">Go to ASAP/src/docs</a>
</p>



---


### 4. If you want to test some HackerOne applications, just run apk_Downloader.py without target.txt

<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/2a97b1d4-f852-419c-88de-32d6aafba598" width="100%" height="100%">
</p>


---


### 5. Go to ASAP/src, run apk_Downloader.py

<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/21e1010e-7bb7-4b55-8b97-69cf1484582f" width="100%" height="100%">
</p>


---


### 6. If you can find ASAP/src/apk_dir, run ASAP.py

<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/7f638f13-2194-4afa-8196-769bba1b3eb8" width="100%" height="100%">
   First, run ApkProcessor.py -> you can find ASAP/src/java_src and ASAP/src/smali_src <br><br>
</p>

<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/f1433f07-a4e8-4cdf-9def-1572af68a939" width="60%" height="60%"> <br>
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/72205656-be6a-4deb-b2f6-b246e5a4335e" width="100%" height="100%">
   Then, run Ananyzer.py
</p>


---


### 7. Go to ASAP/src/ASAP_Web, run app.py

<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/919a55c8-8d68-4b1a-977c-1264b2c67d36" width="100%" height="100%"> <br><br>
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/c7095256-7343-410f-bb50-06ada9a9a22a" width="100%" height="100%">
</p>


---

## Check execution with video

https://github.com/WHS-ASAP/ASAP/assets/149529045/51141726-4eb4-4511-a504-2b5b5a2ed211



## References
([OWASP Mobile Top10](https://owasp.org/www-project-mobile-top-10/))

([BWASP](https://github.com/BWASP/BWASP?tab=readme-ov-file))

([Webview Hijacking](https://ufo.stealien.com/2020-06-18/Deeplink))

</details>

<details>
<summary>Contributor version 1.0</summary>

+ PM: Yeeun Lee ([@Yenniiii](https://github.com/Yenniiii))
   > Develop WebView module
+ Jeongahn Jang ([@jeongahn](https://github.com/jeongahn))
   > Full-Stack(develop web), Development Manager(contribute all of modules)
+ Seoah Myeoung ([@SeoA0703](https://github.com/SeoA0703))
   > Develop Permission, Log module
+ Woohyun Son ([@emerards](https://github.com/emerards))
   > Develop SQL_Injection
+ Yebean Kim ([@kimyebean](https://github.com/kimyebean))
   > Develop Crypto module
+ Yunseong Lee ([@hansowon](https://github.com/hansowon))
   > Develop DeepLink module
+ Yuwon Seol ([@AR3CIA](https://github.com/AR3CIA))
   > Develop HardCoded module
---

</details>

<details>
<summary>Contributor version 2.0</summary>

+ PM : Jeongahn Jang ([@jeongahn](https://github.com/jeongahn))
   > Develop SQL_Injection, Log module
+ Yeeun Lee ([@Yenniiii](https://github.com/Yenniiii))
   > Develop WebView, DeepLink module
+ Seoah Myeoung ([@SeoA0703](https://github.com/SeoA0703))
   > Develop Permission module
+ Yuwon Seol ([@AR3CIA](https://github.com/AR3CIA))
   > Develop HardCoded module
---
+ Mentor: Joowon Kim ([@arrester](https://github.com/arrester))
+ PL: Seonggwang Park ([@n0paew](https://github.com/n0paew))
---



## Acknowledgement
This work was supported by Korea Information Technology Research Institute (KITRI) 2nd WhiteHat School (WHS) Program.

[Project Name: APP in Security (ASAP) Project]

</details>
