# ASAP
This WhiteHat School(WHS) Project is an *open-source*, analysis tool to support for App Vulnerability Manual Analysis Hackers and App Developers.  

The ASAP tool basically provides possible locations for vulnerabilities in code obtained using the jadx decompiler. 

ASAP only supports static analysis. 


---
Scope of Vulnerabilities in ASAP: 
   + WebView
     > In the activity "exported="true", verify that external intent is being loaded into the loadURL, javascript is enabled, and that there is a method to apply javascriptinterface.
   + DeepLink
     > Output [scheme://host/path] from Androidmanifest.xml, parameter detection through smali code function, host/path, URL matching method, JavascriptInterface detection
   + SQL_Injection
     > Detects code that runs SQL in Java code and code that prevents SQL injection
   + HardCoded
     > API Key or Credentials inside the source code. 
   + Permission
     > Extract Permission from AndroidManifest.xml in source code.
   + Insecure_DataStorage (Crypto)
     > Encryption pattern detection in source code on the path where both shared and pref enter
   + Insecure_Logging (LogE)
     > Detect logs that output sensitive information from Java code
---


## ASAP Tool Guide

[guide-ko-documentation](/ASAP/GUIDE_ko.md)
[guide-en-documentation](/ASAP/GUIDE_en.md)

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

---

### 3. If you want to set target applications, go to ASAP/src/docs/target.txt and write app package name
Go to ASAP/src, run apk_Downloader.py
<p align="center">

   <img src="https://github.com/user-attachments/assets/9ccac071-9885-4771-8ccc-a1ccbb58c89a" width="100%" height="100%">
<br>
   <a href="https://github.com/WHS-ASAP/ASAP/blob/readme/src/docs/Readme.md">Go to ASAP/src/docs</a>
</p>

---

### 4. If you want to test some HackerOne applications, just run apk_Downloader.py without target.txt

<p align="center">
   <img src="https://github.com/user-attachments/assets/8eaaab15-d54e-4947-9c67-8a61a83444f9" width="100%" height="100%"></a>
</p>

---

### 5. If you can find ASAP/src/apk_dir, run ASAP.py

<p align="center">
   <img src="https://github.com/user-attachments/assets/d29c845e-9b22-4b42-ada9-f37025475156" width="100%" height="100%"> </a>
   First, run ApkProcessor.py -> you can find ASAP/src/java_src and ASAP/src/smali_src <br><br>
</p>

---

### 6. Go to ASAP/src/ASAP_Web, run app.py

<p align="center">
   <img src="https://github.com/user-attachments/assets/727a4ef9-89a1-48c7-978c-9187638ba77c" width="100%" height="100%"> </a>
</p>

---

## Check execution with video

https://github.com/WHS-ASAP/ASAP/assets/149529045/51141726-4eb4-4511-a504-2b5b5a2ed211

## References
([OWASP Mobile Top10](https://owasp.org/www-project-mobile-top-10/))

([BWASP](https://github.com/BWASP/BWASP?tab=readme-ov-file))

([Webview Hijacking](https://ufo.stealien.com/2020-06-18/Deeplink))



## Contributor

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
+ Mentor: Joowon Kim ([@arrester](https://github.com/arrester))
+ PL: Seonggwang Park ([@n0paew](https://github.com/n0paew))
---



## Acknowledgement
This work was supported by Korea Information Technology Research Institute (KITRI) 2nd WhiteHat School (WHS) Program.

[Project Name: ASAP(Security in APP) Project]
