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

| 모듈 | 규칙 수 | 검사 항목 |
|---|---:|---|
| SQL_Injection | 3 | SQL 쿼리, 쿼리 인자, Content Provider 접근 설정 |
| WebView | 10 | URI 로딩, JavaScript 브리지, 파일 접근, WebView 보안 설정 |
| DeepLink | 4 | URI 처리, App Links 설정, Intent 전달 |
| HardCoded | 5 | 코드에 포함된 자격 증명, 토큰, API 키, 개인 키 |
| Permission | 7 | 권한, 외부 공개 컴포넌트, 디버깅, PendingIntent 설정 |
| Insecure_DataStorage | 12 | Preferences, 암호화, 키, IV, 백업, Firebase 데이터베이스 경로·규칙 |
| Insecure_Logging | 2 | 앱 및 HTTP 로그의 민감 정보 |

세부 내용은 [규칙 카탈로그](docs/rule-catalog.md) 또는 `python3 -m asap rules`로 확인할 수 있습니다.

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

### Firebase Realtime Database

`Insecure_DataStorage` 모듈은 Firebase 데이터베이스 호스트와 소스의 `getReference()` / `child()` 경로를 수집합니다. 로컬 Security Rules와 내보낸 JSON의 child 경로를 순회하면서 조건 없는 읽기·쓰기 허용을 확인하고, 데이터 경로와 값의 타입을 기록합니다. 실제 데이터 값은 리포트에 포함하지 않습니다. Firebase 항목을 열면 리포트 안에서 하위 경로를 검색할 수 있습니다.

프로젝트의 로컬 파일을 APK 또는 소스 분석에 함께 전달합니다.

```bash
python3 -m asap scan ./sample.apk -o results/firebase \
  --firebase-rules ./database.rules.json \
  --firebase-data ./firebase-export.json
```

분석 입력 안에서는 `database.rules.json`·`firebase.rules.json` 규칙 파일과 `firebase-export.json`·`database-export.json`·`rtdb-export.json` 데이터 파일을 자동으로 인식합니다. 옵션으로 직접 첨부하는 파일은 이름이 달라도 됩니다. 웹 대시보드에서는 [설정 파일](docs/toolchain.md#firebase-local-inputs)로 전달합니다.

로컬 파일을 분석하며 Firebase 서버에 요청을 보내지 않습니다. 트리는 최대 4,096개 노드·64단계까지 순회하며, 순회 중단·잘못된 입력·평가하지 못한 규칙 조건은 분석 범위 진단에 표시합니다.

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

- Jeongahn Jang ([@jeongahn](https://github.com/jeongahn))

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
