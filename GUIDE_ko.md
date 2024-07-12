## ASAP Tool Guide
### 1. 초기 설정
```
git clone https://github.com/WHS-ASAP/ASAP.git
cd ASAP
pip install -r requirements.txt
```
---

### 2. jar파일 추가
디컴파일을 위해 ASAP/src/tools/jadx/lib/ 경로에 jadx-dev-all.jar 파일을 추가해 줍니다. 
<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/242397f6-c92a-4900-962c-f4ef7e854b45" width="100%" height="100%">
</p>

---


### 3. target.txt에 앱 패키지 지정
다운로드 받고 싶은 앱이 있다면 ASAP/src/docs/ 경로에 존재하는 target.txt에 해당 앱의 패키지 이름을 지정해야 합니다.
<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/24f76541-f2f5-4d1d-9356-1ea324c7c614" width="100%" height="100%">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/9c5db5d1-6c0c-4267-a876-98d1df9c86c1" width="100%" height="100%"> <br>
   <a href="https://github.com/WHS-ASAP/ASAP/blob/readme/src/docs/Readme.md">Go to ASAP/src/docs</a>
</p>

---


### 4. 해커원 대상 앱 다운로드
만약 해커원에 존재하는 앱을 대상으로 다운로드 하고 싶다면, apk_Downloader.py를 실행시킵니다.
첫 번째로, 해커원에 등록된 앱의 인덱스 값을 지정합니다.

<p align="center">
   <img src="https://github.com/user-attachments/assets/917f92db-d511-46ef-9fe2-0b8c0acefd6d" width="100%" height="100%">
</p>

그다음 분석하고 싶은 앱의 개수를 지정해줍니다.
<p align="center">
   <img src="https://github.com/user-attachments/assets/0b836b5b-73f5-44cf-ae72-0c79aa9ac37c" width="100%" height="100%">
</p>

다음과 같이 지정을 해준다면 해커원에 등록돼 있는 15번째 앱부터 3개의 앱을 다운로드 할 수 있습니다.

---


### 5. apk 파일 다운로드
3번에서 apk 패키지 명을 지정해놨다면, 바로 apk_Downloader.py를 실행시킵니다.

<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/21e1010e-7bb7-4b55-8b97-69cf1484582f" width="100%" height="100%">
</p>

이러면 'target.txt'에 적혀있는 패키지를 대상으로 다운로드를 진행하게 됩니다.

---


### 6. 디컴파일 및 분석 시작
이제 apk 파일이 준비됐다면 ASAP.py를 실행시켜 apk 파일을 디컴파일 한 후 분석을 시작합니다.
<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/7f638f13-2194-4afa-8196-769bba1b3eb8" width="100%" height="100%">
</p>
ASAP.py를 실행시키면 apk_dir에 있는 apk들을 대상으로 디컴파일을 시도합니다. 그렇게 되면 java_src와 smail_src 파일 내에 디컴파일 된 파일이 저장됩니다.
<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/f1433f07-a4e8-4cdf-9def-1572af68a939" width="100%" height="100%">
</p>
디컴파일이 완료되면 취약점 진단을 시작합니다.
<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/72205656-be6a-4deb-b2f6-b246e5a4335e" width="100%" height="100%">
</p>


---


### 7. app.py 실행 후 분석 결과 확인
분석이 끝나면 ASAP/src/ASAP_Web로 이동한후 app.py를 실행시킵니다.
<p align="center">
   <img src="https://github.com/WHS-ASAP/ASAP/assets/149529045/919a55c8-8d68-4b1a-977c-1264b2c67d36" width="100%" height="100%"> <br>
</p>
이제 브라우저에서 127.0.0.1:5000으로 접속합니다.
<p align="center">
   <br>
   <img src="https://github.com/user-attachments/assets/1a20a0c2-01bb-4f3c-89f4-dbb658e81067" width="100%" height="100%">
</p>


---


### 8. 웹 사이트 설명
메인 페이지 입니다.
상단에는 앱 별로 나온 취약점들의 수치를 선 그래프와 원 그래프로 확인할 수 있습니다.
<p align="center">
   <img src="https://github.com/user-attachments/assets/1a20a0c2-01bb-4f3c-89f4-dbb658e81067" width="100%" height="100%">
</p>

하단의 'History' 테이블이나 좌측에 있는 'PACKGE LIST'의 패키지명을 클릭하면 해당 패키지의 분석 결과를 확인할 수 있습니다.
<p align="center">
   <img src="https://github.com/user-attachments/assets/21e67c19-813b-4575-90c1-ecdb95c8efb0" width="100%" height="100%">
</p>

취약점 상세 페이지 에서는 해당 패키지 내에서 나온 취약점의 경로, 취약점 종류, 해당 취약점의 위험도 등을 파악할 수 있습니다.
테이블에 있는 취약점들 중 하나를 클릭하면 해당 취약점의 상세 설명을 확인할 수 있습니다.
<p align="center">
   <img src="https://github.com/user-attachments/assets/c14d6c6f-7c4d-48f0-a2fd-00e78becb9ef" width="100%" height="100%">
   <img src="https://github.com/user-attachments/assets/01649dd0-02ef-473e-a664-61594109da57" width="100%" height="100%">
</p>

이 페이지에서는 취약점 발생 원리, 취약점 악용 가능성, 관련된 CVE 등을 보여주고. 하단에는 나온 취약점을 상세히 표시해 줍니다.