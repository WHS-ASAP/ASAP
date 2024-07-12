## ASAP Tool Guide
### 1. Getting Started
```
git clone https://github.com/WHS-ASAP/ASAP.git
cd ASAP
pip install -r requirements.txt
```
---

### 2. Add jar file
Add the jadx-dev-all.jar file to the ASAP/src/tools/jadx/lib/path.
<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/242397f6-c92a-4900-962c-f4ef7e854b45" width="100%" height="100%">
</p>

---


### 3. Specify the app package in target.txt
If you have an app that you want to download, you must specify the package name of that app in target.txt, which exists in the ASAP/src/docs/ path.
<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/24f76541-f2f5-4d1d-9356-1ea324c7c614" width="100%" height="100%">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/9c5db5d1-6c0c-4267-a876-98d1df9c86c1" width="100%" height="100%"> <br>
   <a href="https://github.com/WHS-ASAP/ASAP/blob/readme/src/docs/Readme.md">Go to ASAP/src/docs</a>
</p>

---


### 4. Download HackerOne Target App
If you want to download apps that exist on hacker sources, run apk_Downloader.py.
First, specify the index value of the app registered with the hacker source.

<p align="center">
   <img src="https://github.com/user-attachments/assets/917f92db-d511-46ef-9fe2-0b8c0acefd6d" width="100%" height="100%">
</p>

Then, specify the number of apps you want to analyze.
<p align="center">
   <img src="https://github.com/user-attachments/assets/0b836b5b-73f5-44cf-ae72-0c79aa9ac37c" width="100%" height="100%">
</p>

If you designate it as follows, you can download three apps from the 15th app registered in HackerOne.

---


### 5. Download apk file
If you save the apk package name in target.txt, run apk_Downloader.py immediately.

<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/21e1010e-7bb7-4b55-8b97-69cf1484582f" width="100%" height="100%">
</p>

Then, you will download the package written on target.txt.

---


### 6. Start Decompiling and Analysis
Now, when the apk file is ready, run ASAP.py to decompile the apk file and start analyzing it.
<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/7f638f13-2194-4afa-8196-769bba1b3eb8" width="100%" height="100%">
</p>
Running ASAP.py will attempt to decompile the apks in apk_dir, which will save the decompiled files within the java_src and smail_src files
<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/f1433f07-a4e8-4cdf-9def-1572af68a939" width="100%" height="100%">
</p>
Upon completion of the decompile, start diagnosing the vulnerability.
<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/72205656-be6a-4deb-b2f6-b246e5a4335e" width="100%" height="100%">
</p>


---


### 7. Run app.py and view analysis results
When you are done analyzing, go to ASAP/src/ASAP_Web and run app.py
<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/919a55c8-8d68-4b1a-977c-1264b2c67d36" width="100%" height="100%"> <br>
</p>
Now go to 127.0.0.1:5000 in your browser.
<p align="center">
   <br>
   <img src="https://github.com/user-attachments/assets/1a20a0c2-01bb-4f3c-89f4-dbb658e81067" width="100%" height="100%">
</p>


---


### 8. Website Description
This is the main page.
At the top, you can check the number of vulnerabilities for each app with a line graph and a circle graph.
<p align="center">
   <img src="https://github.com/user-attachments/assets/1a20a0c2-01bb-4f3c-89f4-dbb658e81067" width="100%" height="100%">
</p>

Click on the history table below or the package name on the left of the PACKGE LIST to see the results of that package's analysis.

<p align="center">
   <img src="https://github.com/user-attachments/assets/21e67c19-813b-4575-90c1-ecdb95c8efb0" width="100%" height="100%">
</p>

The Vulnerability Details page allows you to determine the path, type of vulnerability, and risk of vulnerability within the package.
Click on one of the vulnerabilities in the table to see the detailed description of the vulnerability.

<p align="center">
   <img src="https://github.com/user-attachments/assets/c14d6c6f-7c4d-48f0-a2fd-00e78becb9ef" width="100%" height="100%">
   <img src="https://github.com/user-attachments/assets/01649dd0-02ef-473e-a664-61594109da57" width="100%" height="100%">
</p>

This page shows the principle of vulnerability, potential vulnerability, related CVE, etc. and details the vulnerabilities shown at the bottom.