# Option

## -i [number]

- 사용자가 직접 apk_dir에 넣어놔야 시작 가능, number만큼 scanning

## -d

- apk_download 기능을 사용하는 옵션 : 원하는 앱을 입력하면 그 앱의 apk 파일을 따로 다운 받아서 apk_dir에 저장 후 해당 앱에 대해서 스캐닝 되도록

## -dh

- apk_download 기능을 사용하는데, hackerone에 bugbounty로 올라온 latest 10개 앱들을 crawling후 해당 앱들을 다운받아서 apk_dir에 저장 후 10개 앱에 대해서 스캐닝되도록

## 미정

## 실행방법

python3 ASAP.py -dh [분석 옵션]
