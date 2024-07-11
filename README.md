# ASAP
This WhiteHat School(WHS) Project is an *open-source*, analysis tool to support for App Vulnerability Manual Analysis Hackers and App Developers.  

The ASAP tool basically provides possible locations for vulnerabilities in code obtained using the jadx decompiler. 

ASAP only supports static analysis. 


---
Scope of Vulnerabilities in ASAP: 
   + WebView
     > Detect if you use an external intent as an activity target with [exported="true"] exported from androidmanifest.xml and load the intent with loadURL => webview vulnerability detection
Check presence of function that allows file access with javascripted function in same activity => xss vulnerability detection
   + DeepLink
     > Print [scheme://host/path] from Androidmanifest.xml, detection of parameters through getQueryParameter function in smali code, adjustable host/path through addURI function, url matching scheme through 'Uri; ->parse, JavascriptInterface Detection of JavascriptInterface Available in WebView via JavascriptInterface Annotation, addJavascriptInterface Detection =>Redirect Vulnerability
   + SQL_Injection
     > SQL execution statement in Java code, SQL injection prevention code detection
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
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/242397f6-c92a-4900-962c-f4ef7e854b45" width="60%" height="60%">
</p>

---


### 3. If you want to set target applications, go to ASAP/src/docs/target.txt and write app package name

<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/24f76541-f2f5-4d1d-9356-1ea324c7c614" width="70%" height="70%">
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


### 6. If you can find ASAP/src/apk_dir, run ApkProcessor.py

<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/7f638f13-2194-4afa-8196-769bba1b3eb8" width="100%" height="100%">
</p>


---


### 7. If you can find ASAP/src/java_src and ASAP/src/smali_src, run Analyzer_test.py

<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/29048756-c68f-4a9c-b49b-b939643274a7" width="60%" height="60%"> <br><br>
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/72205656-be6a-4deb-b2f6-b246e5a4335e" width="100%" height="100%">
</p>


---


### 8. Go to ASAP/src/ASAP_Web, run app.py

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

[Project Name: APP in Security (ASAP) Project]
