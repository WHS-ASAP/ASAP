# ASAP

English · [한국어](README_ko.md)

ASAP is an open-source Android static analysis tool for security reviewers and app developers. Analyze APKs or source code, inspect findings across seven modules, and manage each APK in its own workspace.

## Features

- APK, APKS, XAPK, and source directory analysis.
- APK workspaces with scan history, names, notes, archiving, and rescanning.
- Seven analysis modules with 43 rules and module-specific review guides.
- Searchable findings with file locations, code evidence, severity, and review notes.
- HTML, JSON, and SARIF reports, plus baselines and CI thresholds.
- Local CLI and browser interface.

## Getting started

Use **Python 3.11 or later**. Install JADX to analyze DEX code in APKs; Apktool is an optional companion tool. See [tool setup](docs/toolchain.md) for Java requirements and tool paths.

```bash
git clone --branch v3 https://github.com/WHS-ASAP/ASAP.git
cd ASAP
python3 -m asap doctor
python3 -m asap web --workspace .asap-workspace --port 8765
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765) and upload an APK. Press `Ctrl+C` in the terminal to stop the server. On Windows, use `py -3` or `python` in place of `python3`.

To set local tool paths, copy [config.tools.example.json](examples/config.tools.example.json), edit `jadx` and `apktool`, and pass the file when starting ASAP:

```bash
python3 -m asap web --config my-config.json
```

## APK workspaces

Each uploaded APK has a workspace containing its metadata, scan history, and module results. Uploading the same file adds a scan to the same workspace. Different file contents create separate workspaces, including different builds with the same package name.

Give a workspace a name and notes, rerun analysis, or archive it from the list. Open a module to view its findings and review guide, then follow a finding to its code evidence. Archived workspaces can be restored.

Workspace information is stored locally. Finding review statuses and notes are stored in the browser; export and import review JSON to move them between browsers. See [workspace usage](docs/workspaces.md) for details.

## Analysis modules

| Module | Rules | Checks |
|---|---:|---|
| SQL_Injection | 3 | SQL queries, query parameters, and Content Provider access |
| WebView | 10 | URI loading, JavaScript bridges, file access, and WebView security settings |
| DeepLink | 4 | URI handlers, App Links configuration, and Intent forwarding |
| HardCoded | 5 | Embedded credentials, tokens, API keys, and private keys |
| Permission | 7 | Permissions, exported components, debugging, and PendingIntent settings |
| Insecure_DataStorage | 12 | Preferences, cryptography, keys, IVs, backups, and Firebase database paths and rules |
| Insecure_Logging | 2 | Sensitive application and HTTP logging |

See the [rule catalog](docs/rule-catalog.md), or run `python3 -m asap rules`.

## CLI

```bash
# Analyze an APK using tools available on PATH
python3 -m asap scan ./sample.apk -o results/sample

# Set decompiler paths explicitly
python3 -m asap scan ./sample.apk -o results/sample \
  --jadx /absolute/path/jadx/bin/jadx \
  --apktool /absolute/path/apktool.jar

# Analyze source code or existing JADX output
python3 -m asap scan ./decompiled-app -o results/source

# Analyze an APKS or XAPK archive
python3 -m asap scan ./sample.apks -o results/splits

# Run selected modules
python3 -m asap scan ./decompiled-app -o results/selected \
  --categories WebView,DeepLink

# Try the included sample sources
python3 -m asap scan tests/fixtures/demo -o results/demo
```

Configuration files control modules, exclusions, limits, tool paths, and suppressions. Start with [config.example.json](examples/config.example.json) and pass `--config my-config.json`. Use `--no-decompile` to inspect recoverable XML and assets without invoking decompilers; DEX coverage is reported as incomplete.

### Firebase Realtime Database

The `Insecure_DataStorage` module inventories Firebase database hosts and source-level `getReference()` / `child()` paths. It also walks local Security Rules and exported JSON through their child paths, identifying unconditional read/write grants and listing exported paths and value types. Scalar data values are omitted from the report. Open a Firebase finding to search its child paths in the report.

Attach your project's local files to an APK or source scan:

```bash
python3 -m asap scan ./sample.apk -o results/firebase \
  --firebase-rules ./database.rules.json \
  --firebase-data ./firebase-export.json
```

Inside scanned inputs, rules named `database.rules.json` or `firebase.rules.json` and data named `firebase-export.json`, `database-export.json`, or `rtdb-export.json` are recognized automatically. Explicit attachments can use any filename. Dashboard scans accept the same files through [configuration](docs/toolchain.md#firebase-local-inputs).

Analysis uses local files and makes no Firebase requests. Tree traversal is limited to 4,096 nodes and 64 levels; incomplete traversal, malformed inputs, and unevaluated rule conditions appear in coverage diagnostics.

## Reports

Each scan writes three files to the output directory:

| File | Use |
|---|---|
| `report.html` | Open in a browser to explore findings, evidence, module guides, and review notes |
| `report.json` | Structured analysis results and coverage information |
| `report.sarif` | SARIF 2.1.0 results for compatible development tools |

Use `--legacy-json` to also write `legacy_findings.json`. The HTML report supports module, severity, review status, and text filters, with review record import and export.

## Baselines and CI

```bash
python3 -m asap baseline results/sample/report.json -o baseline.json
python3 -m asap scan ./sample.apk -o results/next \
  --baseline baseline.json --only-new --fail-on high --strict
python3 -m asap diff results/sample/report.json results/next/report.json
```

`--fail-on` sets the severity threshold, `--only-new` applies it to findings outside the baseline, and `--strict` fails scans with coverage diagnostics. Exit codes are `0` for completion below the threshold, `1` when the threshold is met, `2` for errors or strict coverage diagnostics, and `130` for interruption.

## Documentation

[Workspaces](docs/workspaces.md) · [Tool setup](docs/toolchain.md) · [Rules](docs/rule-catalog.md) · [Architecture](docs/architecture.md) · [Testing](docs/testing.md) · [Security](docs/security.md)

## Contributor version 3.0

- Jeongahn Jang ([@jh4nks](https://github.com/jh4nks))

## License

[MIT](LICENSE)

## v1 / v2 archive

Tool guides and credits for earlier versions. The corresponding source is available on the [main branch](https://github.com/WHS-ASAP/ASAP/tree/main).

<details>
<summary>v1 / v2 — original tool guide</summary>

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
