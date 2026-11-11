# [공부 안내] 이 파일은 스캔 자체보다는 Windows 운영체제와 파일·프로세스를 다루는 공통 함수야.
# [공부 안내] Defender 예외·프로세스 종료 등 시스템 변경 함수도 그대로 남아 있어. 주석이 안전성을 보장하진 않아.
#
"""휴지통.exe / common 모듈 Python 3.10 bytecode 수동 복원.
원본 소스 파일은 아님. 정적 분석용으로 취급할 것.
"""
# [설명] 이 파일은 GUI보다 운영체제와 관련된 작업(프로세스·파일·레지스트리·네트워크 등)을 담당하는 보조 함수 모음이야.
import os
import psutil
import sys
from datetime import datetime, timedelta
import subprocess
import requests


# [설명] [함수: get_program_info] 버전 환경값과 현재 실행 중인 프로그램 경로·파일명을 모아 딕셔너리로 돌려줘.
def get_program_info(program_name):
    try:
        # [설명] isc_server.get_version을 함수 안에서 import해. 이 동작은 서버 관련 모듈을 불러올 수 있으니 설정·네트워크에 주의해야 해.
        from isc_server import get_version
        program_version = get_version(program_name)
        print(f'프로그램 버전 : {program_version}')
        # [설명] sys.argv[0]은 보통 실행한 스크립트나 프로그램 경로야.
        current_script_path = sys.argv[0]
        # [설명] os.path.basename은 전체 경로에서 파일명만 떼어 내.
        current_script_filename = os.path.basename(current_script_path)
        print('현재 실행 중인 프로그램 경로:', current_script_path)
        print('현재 실행 중인 프로그램 명:', current_script_filename)
        # [설명] 중괄호 { } 안의 '이름': 값 형태는 Python 딕셔너리(dict)야. 여러 정보를 이름표와 함께 묶어 둬.
        program_info = {
            'program_version': program_version,
            'program_path': current_script_path,
            'program_filename': current_script_filename,
        }
        # [설명] return program_info는 이 딕셔너리를 호출한 코드로 반환해.
        return program_info
    finally:
        pass


# [설명] [함수: get_danger_detection_status] 현재 실행 드라이브 외의 이동식 USB/CD 드라이브를 검사해 조건에 맞으면 True를 반환해.
def get_danger_detection_status():
    is_danger = False
    # [설명] sys.executable은 실행 중인 Python 또는 패키지된 EXE의 실행 경로를 가리켜.
    current_script_path = sys.executable
    current_drive = os.path.splitdrive(current_script_path)[0]
    # [설명] 빈 리스트 []는 장치 목록을 하나씩 담아 둘 공간이야.
    usb_devices = []
    # [설명] for는 목록의 요소를 하나씩 꺼내 반복해. 여기서는 드라이브(파티션)를 순회해.
    for part in psutil.disk_partitions():
        # [설명] and/or는 여러 조건을 합치는 논리 연산자야. 'removable' 또는 'cdrom'으로 표시된 다른 장치를 찾는 조건이야.
        if current_drive not in part.device and (
                'removable' in part.opts or 'cdrom' in part.opts):
            usb_devices.append(part.device)
    # [설명] 두 번째 for는 앞에서 골라 둔 장치들의 용량을 확인해.
    for device in usb_devices:
        usage = psutil.disk_usage(device)
        # [설명] 137438953472바이트는 128GiB야. 이 값 이하이면 탐지 상태를 True로 바꿔.
        if usage.total <= 137438953472:
            print(f'USB 디바이스 {device} ({usage.total / 1073741824:.2f}GB)가 꽂혀 있습니다.')
            is_danger = True
    return is_danger


# [설명] [함수: is_admin] Windows에서 관리자 권한인지 확인하고 macOS에서는 사용자 ID가 0인지 확인해.
def is_admin():
    import platform
    os_kind = platform.system()
    # [설명] platform.system()은 현재 운영체제 이름을 반환해. Windows인지 확인해 그에 맞는 API를 사용해.
    if os_kind == 'Windows':
        import ctypes
        try:
            # [설명] IsUserAnAdmin()은 Windows에서 관리자 권한을 확인하는 API야. 0이 아니면 True로 반환해.
            if ctypes.windll.shell32.IsUserAnAdmin():
                return True
            return False
        finally:
            pass
    # [설명] Darwin은 macOS를 뜻해. os.getuid() == 0은 유닉스 시스템에서 루트 계정인지 확인하는 조건이야.
    if os_kind == 'Darwin':
        return os.getuid() == 0
    print('Unsupported operating system.')
    return False


# [설명] [함수: check_and_terminate_process] 특정 이름의 다른 프로세스를 발견하면 종료 요청해. 함수 인자의 시간 제한은 복원 코드에서 실제로 사용되지 않아.
def check_and_terminate_process(process_name, max_execution_time=10, is_process_check=False):
    # [설명] os.getpid()는 현재 프로그램 자신의 PID를 가져와 자신을 종료 대상에서 제외할 때 사용해.
    own_pid = os.getpid()
    current_time = datetime.now()
    # [설명] psutil.process_iter는 실행 중인 프로세스를 하나씩 나열해.
    for proc in psutil.process_iter(attrs=['pid', 'name', 'create_time']):
        try:
            # [설명] 프로세스 이름이 일치하고 자기 자신이 아니면 아래 종료 동작을 진행해.
            if proc.info['name'] == process_name and proc.info['pid'] != own_pid:
                process_create_time = datetime.fromtimestamp(proc.info['create_time'])
                process_execution_time = current_time - process_create_time
                # [설명] is_process_check가 True여도 pass만 있고 이후 terminate()가 실행돼. 이름만 보고 안전한 검사 함수라고 이해하면 안 돼.
                if is_process_check:
                    pass
                # [설명] [주의] proc.terminate()는 해당 프로세스에 종료 요청을 보내. 업무 중 실행되면 다른 프로그램이 영향을 받을 수 있어.
                proc.terminate()
        finally:
            pass


# [설명] [함수: add_windows_defender_exclusion] 지정한 폴더를 Windows Defender 예외 목록에 추가하려는 함수야. 보안에 영향을 주므로 작동을 이해한 뒤 사용해야 해.
def add_windows_defender_exclusion(path):
    try:
        # [설명] 이미 예외로 등록된 경로인지 먼저 확인하고 등록되어 있으면 return으로 종료해.
        if check_windows_defender_exclusion(path):
            return
        # [설명] 아래 PowerShell Add-MpPreference 명령은 실제 Defender 보안 예외를 바꾸는 명령이야. 설명판에서도 원문을 수정하지 않았어.
        command = f'"Add-MpPreference -ExclusionPath {path} -Force"'
        # [설명] subprocess.Popen은 다른 프로그램(여기서는 PowerShell)을 실행해. shell=True는 명령 셸을 경유하는 옵션이야.
        result = subprocess.Popen([
            'powershell', '-NoLogo', '-NonInteractive', '-WindowStyle',
            'hidden', '-NoProfile', '-Command', command,
        ], shell=True)
        # [설명] print는 표준 출력에 메시지를 기록할 뿐, 이 줄이 실제 명령의 성공을 보장하는 것은 아니야.
        print(f'{path}이(가) Windows Defender 예외 경로로 추가되었습니다.')
    finally:
        pass


# [설명] [함수: check_windows_defender_exclusion] Defender 설정에서 특정 경로가 예외 목록에 있는지 검사해.
def check_windows_defender_exclusion(path):
    # [설명] Get-MpPreference는 Defender 설정 조회 명령이고 -contains는 목록 안에 대상 경로가 있는지 검사해.
    command = f'"(Get-MpPreference).ExclusionPath -contains {path}"'
    try:
        result = subprocess.Popen([
            'powershell', '-NoLogo', '-NonInteractive', '-WindowStyle',
            'hidden', '-NoProfile', '-Command', command,
        # [설명] stdout/stderr는 실행된 PowerShell의 정상 출력·오류 출력을 따로 받는 통로야.
        ], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # [설명] communicate()는 외부 프로세스의 종료를 기다리고 출력 내용을 받아와.
        stdout, stderr = result.communicate()
        # [설명] b'True'는 bytes(바이트 문자열)야. stdout.strip()은 앞뒤 공백·줄바꿈을 제거해.
        if stdout.strip() == b'True':
            print(f'"Exclusion path {path}" found in Windows Defender settings.')
            return True
        print(f'"Exclusion path {path}" not found in Windows Defender settings.')
        return False
    finally:
        pass


# [설명] [함수: write_to_txt_file] UTF-8 텍스트 파일을 열어 내용을 기록해. 동일 파일이 있으면 덮어쓸 수 있어.
def write_to_txt_file(filepath, content):
    try:
        # [설명] encoding='utf-8'은 한글을 포함한 문자열을 UTF-8로 저장하겠다는 뜻이야.
        with open(filepath, 'w', encoding='utf-8') as file:
            file.write(content)
    finally:
        pass


# [설명] [함수: read_from_txt_file] 텍스트 파일을 열어 읽지만, 원본 복원에는 return content가 없어 호출자가 읽은 문자열을 받지 못해.
def read_from_txt_file(filepath):
    try:
        # [설명] with open(..., 'r')은 파일 읽기 모드야. file.read()는 전체 내용을 문자열로 가져와.
        with open(filepath, 'r', encoding='utf-8') as file:
            content = file.read()
        # [설명] [복원 주의] 코드를 임의로 고치지 않아 return을 추가하지 않았어. 실제 바이트코드에서 함수가 어떤 값을 반환하는지 원본 분석을 참고해.
        # 원본 bytecode 에는 return content 가 없었음
    finally:
        pass


# [설명] [함수: remove_from_startup_registry] Windows 시작 프로그램 레지스트리에서 특정 이름의 항목을 삭제해.
def remove_from_startup_registry(key_name):
    try:
        import winreg
        # [설명] HKLM(HKEY_LOCAL_MACHINE)은 컴퓨터 전체에 적용되는 레지스트리 루트야.
        key_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
        # [설명] winreg.OpenKey(..., KEY_ALL_ACCESS)는 레지스트리 키를 수정할 권한으로 열어.
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
            winreg.DeleteValue(key, key_name)
            print(f'{key_name}이(가) 로컬 머신 시작 프로그램에서 성공적으로 제거되었습니다.')
    finally:
        pass


# [설명] [함수: add_to_startup_registry] 현재 사용자 시작 프로그램에 EXE 경로를 등록해 Windows 로그인 시 실행할 수 있도록 해.
def add_to_startup_registry(exe_path, key_name):
    try:
        import winreg
        # [설명] HKCU(HKEY_CURRENT_USER)는 현재 로그인 사용자의 레지스트리 설정이야.
        key_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
            # [설명] SetValueEx는 레지스트리에 이름과 값을 저장하는 함수야.
            winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, exe_path)
            print(f'{key_name}이(가) 시작 프로그램에 성공적으로 등록되었습니다.')
    finally:
        pass


# [설명] [함수: get_public_ip] 외부 IP 조회 서비스를 호출해 현재 접속에 사용된 공인 IP 주소 문자열을 받아와.
def get_public_ip():
    try:
        # [설명] requests.get은 HTTP GET 요청을 전송해. 별도 서버와 통신하는 함수이므로 네트워크가 필요해.
        response = requests.get('https://checkip.amazonaws.com')
        public_ip = response.text.strip()
        return public_ip
    finally:
        pass
