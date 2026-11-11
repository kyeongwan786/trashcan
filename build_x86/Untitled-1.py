# 프로그램에 필요한 외부 도구를 가져오는 구간
import base64
import os
import shutil
import sys
import traceback
from datetime import datetime
import ctypes
# sympy의 false를 가져오지만, 이 복원 파일에서는 사용하는 부분이 보이지않음 
from sympy import false
from common import (get_program_info, add_windows_defender_exclusion, is_admin, read_from_txt_file, write_to_txt_file)
# PySide2는 창 버튼 이미지를 그리는 Qt라이브러리이고, QThread는 작업을 별도 스레드로 실행할 때 사용함
from PySide2 import QtCore
from PySide2.QtCore import QFile, QStandardPaths, QThread, Signal, QByteArray, QIODevice
from PySide2.QtGui import QPixmap, QIcon
from PySide2.QtUiTools import QUiLoader
from PySide2.QtWidgets import QMainWindow, QApplication, QMessageBox, QFileDialog

# KaitScan은 kait_extract.py에 정의된 클래스
from kait_extract import KaitScan
from qt_material import apply_stylesheet

userprofile = os.getenv('USERPROFILE')
appdata_temp_dir = os.path.join(userprofile, 'AppData', 'Local', 'Temp')

# 개발 중에는 현재 파일 폴더, EXE로 묶었을 때는 PyInstaller 임시 폴더에서 리소스를 찾도록 함
def resource_path(relative_path):
    # getattr(객체, '이름', 기본값)은 그 속성이 있으면 사용하고 없으면 기본값을 사용 _MEIPASS는 PyInstaller가 압축을 푼 폴더
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    # os.path.join은 경로 구성요소들을 운영체제 방식으로 이어 붙여. return은 완성된 경로를 호출자에게 돌려줌
    return os.path.join(base_path, relative_path)



# exe에 포함된 파일을 지정한 위치로 복사하고 성공하면 True
def copy_file(filename, save_file_path):
    try:
        # 원본 파일이 실제 어느 폴더에 있는지는 resource_path가 결정
        source_path = resource_path(filename)
        # shutil.copy2는 파일을 복사하면서 가능한 메타데이터도 함께 보존됨
        shutil.copy2(source_path, save_file_path)
        return True
    finally:
        pass

class ExtractThread(QThread):
    # Signal()은 Qt에서 다른 객체로 완료 등의 알림을 보낼때 쓸 수 있는 신호
    signal_done = Signal()

    def __init__(self, kait_dll, apils_dll):
        # super().__init__()은 부모 클래스(QThread)의 기본 초기화 코드를 호출
        super().__init__()
        # 이 스레드에서 사용할 KaitScan 객체를 만들어 self.kait_scan에 저장
        self.kait_scan = KaitScan(kait_dll, apils_dll)

    # run은 QThread.start()가 호출되면 별도 스레드에서 실행되는 메서드
    def run(self):
        # start_id_scan()은 KAIT 시작 인증 스캔을 순서대로 요청하는 함수
        self.kait_scan.start_id_scan()

# 창 전체를 관리. QMainWindow를 상속하면 메뉴 중앙 위젯 등의 기본 창 기능을 사용
class ExtractWindow(QMainWindow):
    # 클래스 변수: KAIT DLL 파일 위치를 고정 문자열로 저장한 경로
    kait_dll_path = r'C:\apps\KAIT\KAITIdLib32.dll'
    apils_dll_path = r'C:\Windows\twain_32\VOIMT\apils.dll'

    # 이 __init__은 창 객체가 생성될 때 실행됨.
    def __init__(self):
        super().__init__()
        # 처음에는 창 객체 이미지 폴더 경로 등이 없으므로 None으로 설정
        self.wnd = None
        self.base64_image = None
        self.save_folder_path = None
        self.new_file_name = None
        self.extract_thread = None
        self.is_done = False
        self.kait_dll = None
        self.apils_dll = None
        # UI 설정 함수부터 호출해 버튼과 미리보기 화면을 만듬
        self.init_ui()
        # is_admin()은 현재 프로그램이 관리자 권한으로 실행됐는지 확인
        if not is_admin():
            self.show_alert('관리자 권한으로 실행해주세요.')
            sys.exit(0)
        add_windows_defender_exclusion(appdata_temp_dir)
        try:
            # os.path.exists는 파일 존재 여부를 확인 ctypes.WinDLL은 Windows DLL의 함수를 Python에서 호출할 수 있도록 로드
            if os.path.exists(self.kait_dll_path):
                self.kait_dll = ctypes.WinDLL(self.kait_dll_path)
                # return은 이 __init__의 나머지 실행을 즉시 끝내
                return
            self.show_alert('KAIT 모듈이 설치되어 있지 않습니다. 설치 후 다시 시도해 주세요.')
            sys.exit(0)
        finally:
            pass

    def init_ui(self):
            # [설명] main.ui는 UI 디자이너에서 만든 창 배치 파일이야. source/main.ui에도 복원되어 있어.
            ui_path = resource_path('main.ui')
            ui_file = QFile(ui_path)
            ui_file.close()
            # [설명] QUiLoader().load(...)는 .ui 파일의 버튼과 라벨 등을 읽어 실제 화면 위젯으로 만들어.
            self.wnd = QUiLoader().load(resource_path('main.ui'))
            icon_path = resource_path('dnplayer_104.ico')
            icon = QIcon(icon_path)
            self.setWindowIcon(icon)
            # [설명] setStyleSheet는 CSS와 비슷한 형식으로 이미지 표시 영역의 테두리·배경색을 지정해.
            self.wnd.label_img_viewer.setStyleSheet(
                'QLabel { border: 2px solid black; background-color: white; }')
            self.resize(self.wnd.size())
            # [설명] 원본에서 창 제목을 'LDPlayer 9'로 설정한 부분이야. 프로그램 실제 기능과는 별개야.
            self.setWindowTitle('LDPlayer 9')
            self.setCentralWidget(self.wnd)
            self.center()
            # [설명] clicked.connect(함수)는 버튼을 클릭하면 괄호 안 함수를 실행하도록 연결한다는 뜻이야.
            self.wnd.btn_open_folder.clicked.connect(self.select_folder)
            self.wnd.btn_start.clicked.connect(self.start_extract)

    # [설명] [함수: center] 사용 중인 모니터 크기에서 창이 가운데에 오도록 x, y 좌표를 계산해.
    def center(self):
        primary_screen = QApplication.primaryScreen()
        screen_geometry = primary_screen.geometry()
        window_geometry = self.geometry()            # [설명] //는 소수점 이하를 버리는 정수 나눗셈이야. 남는 화면 공간을 2로 나눠 중앙에 배치해.
        x = (screen_geometry.width() - window_geometry.width()) // 2
        y = (screen_geometry.height() - window_geometry.height()) // 2
        self.move(x, y)
    
        # [설명] [함수: show_alert] 메시지 상자를 띄워 사용자에게 안내해.
    def show_alert(self, message):
        QMessageBox.information(self, '알림', message, QMessageBox.Ok)
    
        # [설명] [함수: select_folder] 사용자가 이미지를 저장할 폴더를 선택하는 동작이야.
    def select_folder(self):
        desktop_path = QStandardPaths.writableLocation(QStandardPaths.DesktopLocation)
            # [설명] getExistingDirectory는 Windows 폴더 선택 창을 표시해. 취소하면 빈 문자열이 나올 수 있어.
        folder = QFileDialog.getExistingDirectory(None, '폴더 선택', desktop_path)
            # [설명] if folder:는 실제 폴더가 선택된 경우에만 아래 코드를 실행한다는 뜻이야.
        if folder:
                print('선택된 폴더:', folder)
                # [설명] self.save_folder_path에 저장 위치를 기억해. 이후 1.jpg 저장할 때 이 값을 사용해.
                self.save_folder_path = folder
                self.wnd.label_folder_path.setText(self.save_folder_path)



    # 시작 버튼을 눌렀을 때 실행되는 핵심 함수. DLL 준비 -> 스캔 스레드 생성 -> 결과 표시 순서로 동작
    def start_extract(self):
        if not self.save_folder_path:
            self.show_alert('저장하실 폴더를 선택해주세요.')
            return
        try:
            # 기존 apils.dll 객체가 있으면 참조를 해제하고 다시 로드하려는 부분. del은 변수 연결을 지우는 동작
            if self.apils_dll:
                del self.apils_dll
                self.apils_dll = None
            # VOIM 드라이버 쪽 보조 DLL(apils.dll)이 있는지 확인
            if os.path.exists(self.apils_dll_path):
                # ctypes.CDLL은 일반 C 호출 규약으로 DLL을 로드하는 방식. 정확한 호출 규약은 DLL API 정의를 확인
                self.apils_dll = ctypes.CDLL(self.apils_dll_path)
            else:
                self.show_alert('스캐너 모듈이 설치되어 있지 않습니다. 설치 후 다시 시도해주세요.')
                sys.exit(0)
        # bare except는 오류 종류를 가리지 않고 잡아. 원본 복원 흐름을 보존했지만, 원인 파악이 어려워질 수 있음
        except:
            return

        # 스캔용 스레드 객체를 만들고 KAIT DLL 객체와 apils.dll 경로 문자열을 전달
        self.extract_thread = ExtractThread(self.kait_dll, self.apils_dll_path)
        # kp_err_msg에 메시지가 들어 있으면 초기화 단계의 오류로 보고 사용자에게 알려줌
        if self.extract_thread.kait_scan.kp_err_msg:
            self.show_aelrt(self.extract_thread.kait_scan.kp_err_msg)
            return
        # 스캔 스레드를 시작한 뒤 스캔 중 중복 클릭을 막기 위해 버튼을 비활성화
        try:
            # QThread.start()는 run()을 별도 스레드에서 호출하게 해
            self.extract_thread_start()
            self.wnd.btn_start.setEnabled(False)
            self.wnd.btn_open_folder.setEnabled(False)
        except Exception as E:
            print(E)
        print('3')
        self.extract_thread.wait()
        self.id_scane_done()

    # 스캔 결과 JSON을 검사하고, 성공한 경우 이미지를 창에 표시하고 1.jpg로 저장
    def id_scan_done(self):
        try:
            try:
                # self.is_done을 False로 되돌림
                self.is_doen = False
                if self.extract_thread.kait_scan.err_code != 0:
                    self.show_alert(f'[{self.extract_thread.kait_scan.err_code}]')
                    self.wnd.btn_start.setEnabled(True)
                    self.wnd.btn_open_folder.setEnabled(True)
                    return
                # ocr_data는 KAIT DLL에서 반환된 JSON을 Python 딕셔너리로 바꾼 결과
                ocr_data = self.extract_thread.kait_scan.ocr_data
                # ID_NAME/ID_TYPE 값은 이미지 표시 조건으로 사용하지 않아. OCR 결과 자체는 있어야 해.
                if not ocr_data:
                    self.show_alert('스캔 결과가 없습니다.')
                    self.wnd.btn_start.setEnabled(True)
                    self.wnd.btn_open_folder.setEnabled(True)
                    return
                # ID_IMG1이 없거나 비어 있으면 이미지 표시를 진행하지 않아.
                if 'ID_IMG1' not in ocr_data or not ocr_data['ID_IMG1']:
                    self.show_alert('신분증 이미지가 정상적으로 인식되지 않았습니다. 다시 시도해주세요.')
                    self.wnd.btn_start.setEnabled(True)
                    self.wnd.btn_open_folder.setEnabled(True)
                    return
                # base64.b64decode는 텍스트 형태로 전송된 이미지 데이터를 실제 바이트로 되돌림
                image_bytes = base64.b64decode(ocr_data['ID_IMG1'])
                # QByteArray는 Qt가 처리할 수 있는 바이트 배열임
                image_bytearray = QByteArray(image_bytes)
                # QPixmap은 Qt에서 이미지 표시 저장을 담당하는 객체
                pixmap = QPixmap()
                # loadFromData는 메모리에 있는 이미지 바이트로 QPixmap을 만듬
                pixmap.loadFromData(image_bytearray)
                # label_img_viewer는 이미지 미리보기 라벨 setPixmap으로 표시하고 중앙 정렬 크기 맞춤을 적용해
                self.wnd.label_img_viewer.setPixmap(pixmap)
                self.wnd.label_img_viewer.setAlignment(QtCore.Qt.AlignCenter)
                self.wnd.label_img_viewer.setScaledContents(True)
                # 사용자가 저장 폴더를 저장했다면 그 폴더에 이미지를 저장
                if self.save_folder_path:
                    pixmap.save(self.save_folder_path + '/1.jpg')
                self.wnd.btn_start.setEnabled(True)
                self.wnd.btn_open_folder.setEnabled(True)
            except Exception as E:
                print (E)
        except Exception as E:
            print(E)
            return

if __name__ == '__main__':
    app = QApplication(sys.argv)
    apply_stylesheet(app, theme='dark_cyan.xml')
    window = ExtractWindow()
    window.show()
    sys.exit(app.exec_())


