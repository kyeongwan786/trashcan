휴지통(1).zip 파이썬 코드 복원 — 2026-10-31

원본 해시(SHA256): 735391d6a0e4acce8c0fb65e903cd044b466725dea643b402a01e197eb9b7e7f

확인 사항
1) EXE의 PyInstaller 표식(MEI cookie) 확인. Python 3.10 / 32bit.
2) 원본 EXE 안에서 PyArmor 런타임/pyarmor 모듈 흔적은 확인되지 않음.
3) PyInstaller CArchive 916개 엔트리 추출, PYZ에 1,734개 모듈 존재.
4) 해당 프로그램의 직접 구성 코드로 Untitled-1, kait_extract, common, isc_server 총 4개 Python 3.10 코드 객체 복원.
5) .py 파일은 본래 소스의 원문이 아닌, 3.10 바이트코드의 변수명/상수/제어흐름을 읽어 사람이 수동 재작성한 것.
6) Python 문법 검사는 통과했지만, 원본 32bit Windows/KAIT 환경에서 재실행되거나 원본과 동작이 100% 동일한지는 검증되지 않았음.
7) 원본의 주석/공백/일부 예외처리 문법을 정확하게 재생할 수 없음. 확정 확인은 analysis/Python310_전체_bytecode_명령어.txt의 명령어 목록 이용.
8) bytecode/*.pyc는 추출한 원본 실행 바이트코드에 Python 3.10 pyc 헤더를 추가한 데이터임(재컴파일된 .pyc 아님).

자료 위치
source/Untitled-1.py — 메인 UI와 스캔 실행·ID_IMG1 저장
source/kait_extract.py — KAIT DLL 호출 및 JSON 반환 처리
source/common.py — 윈도우 관리, Defender 예외 설정
source/isc_server.py — Supabase/외부 네트워크 헬퍼 함수
source/main.ui — EXE에서 추출한 Qt UI 원본
bytecode/ — 네 가지 모듈의 원본 CPython 3.10 코드 객체
analysis/ — 전체 디스어셈블리와 PyInstaller CArchive 파일 목록

보안 관련 주의사항
- common.add_windows_defender_exclusion()은 Windows Defender 예외 경로를 등록하는 코드로, 메인 UI 초기화 시 실제 호출됨.
- isc_server.py에는 upload_id_card()와 save_ocr_data()의 Supabase 전송 관련 함수가 존재하지만, 휴지통 일반 스캔 호출 경로에서 실제 사용되었다는 증거는 없으며 별도 함수 정의임.
- 원본 `.env`와 아이콘 `dnplayer_104.ico`는 실행파일 CArchive에서 확인되지 않았음. 재구성본을 곧바로 실행할 수 있다고 보장하지 않음.
- 이 패키지에는 운영 환경의 고객 데이터/신분증 이미지가 포함되지 않음.
- 기존 원본 EXE와 KAIT DLL은 수정하지 않았음.
