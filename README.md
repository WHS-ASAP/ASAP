# ASAP
This WhiteHat School(WHS) Project is an *open-source*, analysis tool to support for App Vulnerability Manual Analysis Hackers and App Developers.  

The ASAP tool basically provides possible locations for vulnerabilities in code obtained using the jadx decompiler. 

ASAP only supports static analysis. 


---
Scope of Vulnerabilities in ASAP: 
   + WebView
   + DeepLink
   + SQL_Injection
   + HardCoded
   + Permission
   + Insecure_DataStorage (Crypto)
   + Insecure_Logging (LogE)
---



## ASAP Tool Guide
### 1. Getting Started
---
```
git clone https://github.com/WHS-ASAP/ASAP.git
cd ASAP
pip install -r requirements.txt
```
---
### 2. Add ASAP/src/tools/jadx/lib/jadx-dev-all.jar
---
![add jadx-dev-all.jar](https://github.com/WHS-ASAP/ASAP/assets/149529045/242397f6-c92a-4900-962c-f4ef7e854b45)
---
### 3. If you want to set target applications, go to ASAP/src/docs/target.txt and write app package name
---
![target.txt path](https://github.com/WHS-ASAP/ASAP/assets/149529045/24f76541-f2f5-4d1d-9356-1ea324c7c614)
![target.txt readme](https://github.com/WHS-ASAP/ASAP/assets/149529045/2e9ce3a3-b5e1-4ff7-a716-625c0c387d8d)
---
### 4. If you want to test some HackerOne applications, just run apk_Downloader.py without target.txt
---
사진... 이 필요한데 에러 뜸
원래 되지 않았었나?
Error: Target file not found at docs\target.txt
---
### 5. Go to ASAP/src, run apk_Downloader.py
---
나는 403 에러 뜸 누군가 사진 좀
---
### 6. If you can find ASAP/src/apk_dir, run ApkProcessor.py
---
![find apk_src](https://github.com/WHS-ASAP/ASAP/assets/149529045/9c459cfd-4da2-4932-8db5-7ebbc28d8e67)
![run ApkProcessor.py](https://github.com/WHS-ASAP/ASAP/assets/149529045/7f638f13-2194-4afa-8196-769bba1b3eb8)
<img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/9c459cfd-4da2-4932-8db5-7ebbc28d8e67"  width="400" height="500">
---
### 7. If you can find ASAP/src/java_src and ASAP/src/smali_src, run Analyzer_test.py
---
![find java_src and smali_src](https://github.com/WHS-ASAP/ASAP/assets/149529045/29048756-c68f-4a9c-b49b-b939643274a7)
![run Analyzer_test.py](https://github.com/WHS-ASAP/ASAP/assets/149529045/72205656-be6a-4deb-b2f6-b246e5a4335e)
---
### 8. Go to ASAP/src/ASAP_Web, run app.py
---
![cli after running app.py](https://github.com/WHS-ASAP/ASAP/assets/149529045/919a55c8-8d68-4b1a-977c-1264b2c67d36)
![web](https://github.com/WHS-ASAP/ASAP/assets/149529045/8bcf014f-6704-478e-8537-5ff37c6b714e)



## References
([Webview Hijacking](https://ufo.stealien.com/2020-06-18/Deeplink))
([BWASP](https://github.com/BWASP/BWASP?tab=readme-ov-file))
개발하면서 참고한 링크



## Contributor

+ PM: Yeeun Lee ([@Yenniiii](https://github.com/Yenniiii))
   > Develop WebView module
+ Jeongahn Jang ([@jeongahn](https://github.com/jeongahn))
   > Full-Stack(develop web), Development Manager(contribute all of modules)
+ Seoa Myung ([@SeoA0703](https://github.com/SeoA0703))
   > Develop Permission module
+ Woohyun Son ([@emerards](https://github.com/emerards))
   > Develop SQL_Injection
+ Yebean Kim ([@kimyebean](https://github.com/kimyebean))
   > Develop Crypto module
+ Yunsung Lee ([@hansowon](https://github.com/hansowon))
   > Develop DeepLink module
+ Yuwon Sul ([@AR3CIA](https://github.com/AR3CIA))
   > Develop HardCoded module

---
+ Mentor: Joowon Kim ([@arrester](https://github.com/arrester))
+ PL: Sunggwang Park ([@n0paew](https://github.com/n0paew))
---



## Acknowledgement
This work was supported by Korea Information Technology Research Institute (KITRI) 2nd WhiteHat School (WHS) Program.

[Project Name: APP in Security (ASAP) Project]
