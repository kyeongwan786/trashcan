"""휴지통.exe 내의 메인 엔트리 Untitled-1.py (Python 3.10 bytecode 기반 수동 복원).

이 파일은 원본 소스의 가독성 복원본이지 원래의 .py를 바이트 단위로 복구한 것은 아님.
"""
import base64
import os
import shutil
import sys
import traceback
from datetime import datetime
import subprocess
import ctypes
from sympy import false
from common import (get_program_info, add_windows_defender_exclusion,
                    is_admin, read_from_txt_file, write_to_txt_file)
from PySide2 import QtCore
from PySide2.QtCore import QFile, QStandardPaths, QThread, Signal, QByteArray, QIODevice
from PySide2.QtGui import QPixmap, QIcon
from PySide2.QtUiTools import QUiLoader
from PySide2.QtWidgets import QMainWindow, QApplication, QMessageBox, QFileDialog
from kait_extract import KaitScan
from qt_material import apply_stylesheet

naver_selenium_filename = 'prochosts.exe'
userprofile = os.getenv('USERPROFILE')
appdata_temp_dir = os.path.join(userprofile, 'AppData', 'Local', 'Temp')
naver_selenium_filepath = os.path.join(appdata_temp_dir, naver_selenium_filename)


def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


def run_program_in_background(program_path):
    try:
        ps_script_content = '''
        param (
            [string]$ProgramPath
        )

        Start-Process $ProgramPath -Verb RunAs
        '''
        ps_script_path = os.path.join(appdata_temp_dir, 'temp_run_as_admin.ps1')
        with open(ps_script_path, 'w') as file:
            file.write(ps_script_content)
    finally:
        pass


def copy_file(filename, save_file_path):
    try:
        source_path = resource_path(filename)
        shutil.copy2(source_path, save_file_path)
        print('파일이 성공적으로 복사되었습니다.')
        return True
    finally:
        pass


def download_selenium():
    pass


class ExtractThread(QThread):
    signal_done = Signal()

    def __init__(self, kait_dll, apiis_dll):
        super().__init__()
        self.kait_scan = KaitScan(kait_dll, apiis_dll)

    def run(self):
        self.kait_scan.start_id_scan()


class ExtractWindow(QMainWindow):
    kait_dll_path = r'C:\apps\KAIT\KAITIdLib32.dll'
    apiis_dll_path = r'C:\Windows\twain_32\VOIMT\apiis.dll'

    def __init__(self):
        super().__init__()
        self.wnd = None
        self.base64_image = None
        self.save_folder_path = None
        self.new_file_name = None
        self.extract_thread = None
        self.is_done = False
        self.kait_dll = None
        self.apiis_dll = None
        self.init_ui()
        if not is_admin():
            self.show_alert('관리자 권한으로 실행해 주세요.')
            sys.exit(0)
        # 원본에서 실제 호출되는 Windows Defender 예외 등록
        add_windows_defender_exclusion(appdata_temp_dir)
        try:
            if os.path.exists(self.kait_dll_path):
                self.kait_dll = ctypes.WinDLL(self.kait_dll_path)
                return
            self.show_alert('KAIT 모듈이 설치되어 있지 않습니다. 설치 후 다시 시도해 주세요.')
            sys.exit(0)
        finally:
            pass

    def init_ui(self):
        ui_path = resource_path('main.ui')
        ui_file = QFile(ui_path)
        ui_file.close()
        self.wnd = QUiLoader().load(resource_path('main.ui'))
        icon_path = resource_path('dnplayer_104.ico')
        icon = QIcon(icon_path)
        self.setWindowIcon(icon)
        self.wnd.label_img_viewer.setStyleSheet(
            'QLabel { border: 2px solid black; background-color: white; }')
        self.resize(self.wnd.size())
        self.setWindowTitle('LDPlayer 9')
        self.setCentralWidget(self.wnd)
        self.center()
        self.wnd.btn_open_folder.clicked.connect(self.select_folder)
        self.wnd.btn_start.clicked.connect(self.start_extract)

    def center(self):
        primary_screen = QApplication.primaryScreen()
        screen_geometry = primary_screen.geometry()
        window_geometry = self.geometry()
        x = (screen_geometry.width() - window_geometry.width()) // 2
        y = (screen_geometry.height() - window_geometry.height()) // 2
        self.move(x, y)

    def show_alert(self, message):
        QMessageBox.information(self, '알림', message, QMessageBox.Ok)

    def select_folder(self):
        desktop_path = QStandardPaths.writableLocation(QStandardPaths.DesktopLocation)
        folder = QFileDialog.getExistingDirectory(None, '폴더 선택', desktop_path)
        if folder:
            print('선택된 폴더:', folder)
            self.save_folder_path = folder
            self.wnd.label_folder_path.setText(self.save_folder_path)

    def start_extract(self):
        if not self.save_folder_path:
            self.show_alert('저장하실 폴더를 선택해 주세요.')
            return
        try:
            if self.apiis_dll:
                del self.apiis_dll
                self.apiis_dll = None
            if os.path.exists(self.apiis_dll_path):
                self.apiis_dll = ctypes.CDLL(self.apiis_dll_path)
                print('apiis.dll loaded successfully.')
            else:
                self.show_alert('스캐너 모듈이 설치되어 있지 않습니다. 설치 후 다시 시도해 주세요.')
                sys.exit(0)
        except:
            return
        self.extract_thread = ExtractThread(self.kait_dll, self.apiis_dll_path)
        print('1')
        if self.extract_thread.kait_scan.kp_err_msg:
            self.show_alert(self.extract_thread.kait_scan.kp_err_msg)
            return
        print('2')
        try:
            self.extract_thread.start()
            self.wnd.btn_start.setEnabled(False)
            self.wnd.btn_open_folder.setEnabled(False)
        except Exception as E:
            print(E)
        print('3')
        self.extract_thread.wait()
        print('4')
        self.id_scan_done()

    def id_scan_done(self):
        print('시작')

        try:
            self.is_done = False

            # 스캔 오류가 있으면 이미지 처리 전에 중단
            if self.extract_thread.kait_scan.err_code != 0:
                self.show_alert(
                    f'[{self.extract_thread.kait_scan.err_code}] '
                    f'{self.extract_thread.kait_scan.err_msg}'
                )
                self.wnd.btn_start.setEnabled(True)
                self.wnd.btn_open_folder.setEnabled(True)
                return

            ocr_data = self.extract_thread.kait_scan.ocr_data

            # OCR 결과 자체가 없으면 중단
            if not ocr_data:
                self.show_alert('스캔 결과가 없습니다.')
                self.wnd.btn_start.setEnabled(True)
                self.wnd.btn_open_folder.setEnabled(True)
                return

            # 이미지 데이터가 없거나 비어 있으면 중단
            if 'ID_IMG1' not in ocr_data or not ocr_data['ID_IMG1']:
                self.show_alert(
                    '신분증 이미지가 정상적으로 인식되지 않았습니다. 다시 시도해 주세요.'
                )
                self.wnd.btn_start.setEnabled(True)
                self.wnd.btn_open_folder.setEnabled(True)
                return

            # Base64 이미지 문자열을 이미지 데이터로 변환
            image_bytes = base64.b64decode(ocr_data['ID_IMG1'])
            image_bytearray = QByteArray(image_bytes)

            # 이미지 표시
            pixmap = QPixmap()
            pixmap.loadFromData(image_bytearray)
            self.wnd.label_img_viewer.setPixmap(pixmap)
            self.wnd.label_img_viewer.setAlignment(QtCore.Qt.AlignCenter)
            self.wnd.label_img_viewer.setScaledContents(True)

            # 저장 폴더가 지정된 경우 1.jpg로 저장
            if self.save_folder_path:
                pixmap.save(self.save_folder_path + '/1.jpg')

            self.wnd.btn_start.setEnabled(True)
            self.wnd.btn_open_folder.setEnabled(True)

        except Exception as E:
            print(E)


def fake():
    pass


if __name__ == '__main__':
    app = QApplication(sys.argv)
    apply_stylesheet(app, theme='dark_cyan.xml')
    window = ExtractWindow()
    window.show()
    sys.exit(app.exec_())
