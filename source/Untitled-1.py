# [공부 안내] 이 파일은 메인 화면과 저장 흐름을 관리해. 실제 스캔 명령은 kait_extract.py에 있어.
# [공부 안내] 읽는 순서: ExtractWindow.__init__ → init_ui → start_extract → ExtractThread.run → id_scan_done.
# [공부 안내] 이번 주석 추가는 설명만 삽입한 것이며 실행 문장을 바꾸지 않았어.
#
"""휴지통.exe 내의 메인 엔트리 Untitled-1.py (Python 3.10 bytecode 기반 수동 복원).

이 파일은 원본 소스의 가독성 복원본이지 원래의 .py를 바이트 단위로 복구한 것은 아님.
"""
# [설명] 프로그램에 필요한 외부 도구를 가져오는 구간. import는 다른 모듈의 기능을 이 파일에서 쓰겠다는 뜻이야.
import base64
import os
import shutil
import sys
import traceback
from datetime import datetime
import subprocess
import ctypes
# [설명] sympy의 false를 가져오지만, 이 복원 파일에서는 사용하는 부분이 보이지 않아. 원본에서 남은 흔적일 수 있어.
from sympy import false
# [설명] common.py는 관리자 권한 검사, 설정 관련 보조 함수 등이 들어 있는 파일이야.
from common import (get_program_info, add_windows_defender_exclusion,
                    is_admin, read_from_txt_file, write_to_txt_file)
# [설명] PySide2는 창·버튼·이미지를 그리는 Qt 라이브러리이고, QThread는 작업을 별도 스레드로 실행할 때 사용해.
from PySide2 import QtCore
from PySide2.QtCore import QFile, QStandardPaths, QThread, Signal, QByteArray, QIODevice
from PySide2.QtGui import QPixmap, QIcon
from PySide2.QtUiTools import QUiLoader
from PySide2.QtWidgets import QMainWindow, QApplication, QMessageBox, QFileDialog
# [설명] KaitScan은 kait_extract.py에 정의된 클래스야. 스캐너 작업을 그 안에서 처리해.
from kait_extract import KaitScan
from qt_material import apply_stylesheet

# [설명] 아래 경로는 사용자별 임시 폴더야. os.getenv('USERPROFILE')는 Windows 환경변수의 값을 가져와.
naver_selenium_filename = 'prochosts.exe'
userprofile = os.getenv('USERPROFILE')
appdata_temp_dir = os.path.join(userprofile, 'AppData', 'Local', 'Temp')
naver_selenium_filepath = os.path.join(appdata_temp_dir, naver_selenium_filename)


# [설명] [함수: resource_path] 개발 중에는 현재 파일 폴더, EXE로 묶었을 때는 PyInstaller 임시 폴더에서 리소스를 찾도록 해.
def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    # [설명] getattr(객체, '이름', 기본값)은 그 속성이 있으면 사용하고 없으면 기본값을 사용해. _MEIPASS는 PyInstaller가 압축을 푼 폴더야.
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    # [설명] os.path.join은 경로 구성요소들을 운영체제 방식으로 이어 붙여. return은 완성된 경로를 호출자에게 돌려줘.
    return os.path.join(base_path, relative_path)


# [설명] [함수: run_program_in_background] 관리자 실행용 PowerShell 스크립트 문자열을 파일로 저장하는 부분이야. 함수 이름과 달리 여기서 EXE를 바로 실행하지는 않아.
def run_program_in_background(program_path):
    try:
        # [설명] 세 개의 따옴표(''' ... ''')는 여러 줄 문자열을 만들 때 사용해. 아래 문자열은 Python 코드가 아니라 PowerShell 코드야.
        ps_script_content = '''
        param (
            [string]$ProgramPath
        )

        Start-Process $ProgramPath -Verb RunAs
        '''
        # [설명] 임시 폴더에 저장할 .ps1 파일 경로를 조립해.
        ps_script_path = os.path.join(appdata_temp_dir, 'temp_run_as_admin.ps1')
        # [설명] with open(..., 'w')는 파일을 쓰기 모드로 열고 블록을 벗어나면 자동으로 닫아 줘.
        with open(ps_script_path, 'w') as file:
            file.write(ps_script_content)
    # [설명] finally는 예외가 있든 없든 실행되는 구간이야. 여기서는 pass만 있으므로 추가 동작은 없어.
    finally:
        pass


# [설명] [함수: copy_file] EXE에 포함된 파일을 지정한 위치로 복사하고 성공하면 True를 돌려줘.
def copy_file(filename, save_file_path):
    try:
        # [설명] 원본 파일이 실제 어느 폴더에 있는지는 resource_path가 결정해.
        source_path = resource_path(filename)
        # [설명] shutil.copy2는 파일을 복사하면서 가능한 메타데이터도 함께 보존해.
        shutil.copy2(source_path, save_file_path)
        print('파일이 성공적으로 복사되었습니다.')
        # [설명] True는 참(True/성공)을 뜻하는 불리언 값이야.
        return True
    finally:
        pass


# [설명] [함수: download_selenium] 복원 소스에는 pass만 있어 실제 작업을 하지 않는 빈 함수야.
def download_selenium():
    pass


# [설명] [클래스: ExtractThread] 스캔 작업을 GUI 메인 흐름과 구분해 실행하도록 만든 QThread 클래스야.
class ExtractThread(QThread):
    # [설명] Signal()은 Qt에서 다른 객체로 완료 등의 알림을 보낼 때 쓸 수 있는 신호야. 이 복원 파일에서는 signal_done.emit() 호출이 보이지 않아.
    signal_done = Signal()

    # [설명] __init__은 객체가 만들어질 때 자동 실행되는 초기화 함수야. self는 '지금 만들어진 객체 자신'을 뜻해.
    def __init__(self, kait_dll, apiis_dll):
        # [설명] super().__init__()은 부모 클래스(QThread)의 기본 초기화 코드를 호출해.
        super().__init__()
        # [설명] 이 스레드에서 사용할 KaitScan 객체를 만들어 self.kait_scan에 저장해.
        self.kait_scan = KaitScan(kait_dll, apiis_dll)

    # [설명] run()은 QThread.start()가 호출되면 별도 스레드에서 실행되는 메서드야.
    def run(self):
        # [설명] start_id_scan()은 KAIT 시작·인증·스캔을 순서대로 요청하는 함수야. 실제 순서는 kait_extract.py의 해당 함수를 봐.
        self.kait_scan.start_id_scan()


# [설명] [클래스: ExtractWindow] 창 전체를 관리해. QMainWindow를 상속하면 메뉴·중앙 위젯 등의 기본 창 기능을 사용할 수 있어.
class ExtractWindow(QMainWindow):
    # [설명] 클래스 변수: KAIT DLL 파일 위치를 고정 문자열로 저장한 경로야. 앞의 r은 백슬래시를 문자 그대로 취급해.
    kait_dll_path = r'C:\apps\KAIT\KAITIdLib32.dll'
    apiis_dll_path = r'C:\Windows\twain_32\VOIMT\apiis.dll'

    # [설명] 이 __init__은 창 객체가 생성될 때 실행돼. 아래 self.xxx 값들은 창의 상태를 기억하는 변수야.
    def __init__(self):
        super().__init__()
        # [설명] 처음에는 창 객체·이미지·폴더 경로 등이 없으므로 None으로 설정해. None은 '아직 값 없음'이라는 뜻이야.
        self.wnd = None
        self.base64_image = None
        self.save_folder_path = None
        self.new_file_name = None
        self.extract_thread = None
        self.is_done = False
        self.kait_dll = None
        self.apiis_dll = None
        # [설명] UI 설정 함수부터 호출해 버튼과 미리보기 화면을 만들어.
        self.init_ui()
        # [설명] is_admin()은 현재 프로그램이 관리자 권한으로 실행됐는지 확인해.
        if not is_admin():
            self.show_alert('관리자 권한으로 실행해 주세요.')
            sys.exit(0)
        # [설명] [주의] 원본 메인 코드의 기능을 삭제하지 않고 보존한 줄이야. Defender 예외 경로 등록은 보안 범위를 낮출 수 있으니 실행 전에 인지해야 해.
        # 원본에서 실제 호출되는 Windows Defender 예외 등록
        add_windows_defender_exclusion(appdata_temp_dir)
        try:
            # [설명] os.path.exists는 파일 존재 여부를 확인해. ctypes.WinDLL은 Windows DLL의 함수를 Python에서 호출할 수 있도록 로드해.
            if os.path.exists(self.kait_dll_path):
                self.kait_dll = ctypes.WinDLL(self.kait_dll_path)
                # [설명] return은 이 __init__의 나머지 실행을 즉시 끝내. DLL이 존재하면 여기서 초기화 함수가 종료돼.
                return
            self.show_alert('KAIT 모듈이 설치되어 있지 않습니다. 설치 후 다시 시도해 주세요.')
            sys.exit(0)
        finally:
            pass

    # [설명] [함수: init_ui] main.ui를 불러와 버튼·미리보기·폴더 경로 표시를 연결하는 부분이야.
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
        window_geometry = self.geometry()
        # [설명] //는 소수점 이하를 버리는 정수 나눗셈이야. 남는 화면 공간을 2로 나눠 중앙에 배치해.
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

    # [설명] [함수: start_extract] 시작 버튼을 눌렀을 때 실행되는 핵심 함수야. DLL 준비 → 스캔 스레드 생성 → 결과 표시 순서로 동작해.
    def start_extract(self):
        # [설명] 아직 저장 폴더가 선택되지 않았다면 안내하고 return으로 중단해.
        if not self.save_folder_path:
            self.show_alert('저장하실 폴더를 선택해 주세요.')
            return
        # [설명] try는 실행 중 오류가 발생할 수 있는 코드를 묶는 구문이야. 아래 except는 오류가 나면 처리해.
        try:
            # [설명] 기존 apiis.dll 객체가 있으면 참조를 해제하고 다시 로드하려는 부분이야. del은 변수 연결을 지우는 동작이야.
            if self.apiis_dll:
                del self.apiis_dll
                self.apiis_dll = None
            # [설명] VOIM 드라이버 쪽 보조 DLL(apiis.dll)이 있는지 확인해.
            if os.path.exists(self.apiis_dll_path):
                # [설명] ctypes.CDLL은 일반 C 호출 규약으로 DLL을 로드하는 방식이야. 정확한 호출 규약은 DLL API 정의를 확인해야 해.
                self.apiis_dll = ctypes.CDLL(self.apiis_dll_path)
                print('apiis.dll loaded successfully.')
            else:
                self.show_alert('스캐너 모듈이 설치되어 있지 않습니다. 설치 후 다시 시도해 주세요.')
                sys.exit(0)
        # [설명] bare except는 오류 종류를 가리지 않고 잡아. 원본 복원 흐름을 보존했지만, 원인 파악이 어려워질 수 있어.
        except:
            return
        # [설명] 스캔용 스레드 객체를 만들고 KAIT DLL 객체와 apiis.dll 경로 문자열을 전달해.
        self.extract_thread = ExtractThread(self.kait_dll, self.apiis_dll_path)
        print('1')
        # [설명] kp_err_msg에 메시지가 들어 있으면 초기화 단계의 오류로 보고 사용자에게 알려줘.
        if self.extract_thread.kait_scan.kp_err_msg:
            self.show_alert(self.extract_thread.kait_scan.kp_err_msg)
            return
        print('2')
        # [설명] 스캔 스레드를 시작한 뒤 스캔 중 중복 클릭을 막기 위해 버튼을 비활성화해.
        try:
            # [설명] QThread.start()는 run()을 별도 스레드에서 호출하게 해.
            self.extract_thread.start()
            self.wnd.btn_start.setEnabled(False)
            self.wnd.btn_open_folder.setEnabled(False)
        except Exception as E:
            print(E)
        print('3')
        # [설명] [중요] wait()는 스캔 스레드가 끝날 때까지 현재 실행 흐름을 기다리게 해. GUI 스레드에서 호출되어 화면이 '응답 없음'으로 보일 수 있어.
        self.extract_thread.wait()
        print('4')
        # [설명] 스캔 종료 후 id_scan_done()을 직접 호출해 오류 검사·이미지 표시·저장을 진행해.
        self.id_scan_done()

    # [설명] [함수: id_scan_done] 스캔 결과 JSON을 검사하고, 성공한 경우 이미지를 창에 표시하고 1.jpg로 저장해.
    def id_scan_done(self):
        print('시작')
        try:
            try:
                # [설명] self.is_done을 False로 되돌려. 이 복원 소스에서는 이후 이 값을 활용하는 부분이 뚜렷하지 않아.
                self.is_done = False
                # [설명] err_code가 0이 아니면 오류로 판단해. f'...'는 변수값을 문자열 안에 넣는 f-string이야.
                if self.extract_thread.kait_scan.err_code != 0:
                    self.show_alert(f'[{self.extract_thread.kait_scan.err_code}] '
                                    f'{self.extract_thread.kait_scan.err_msg}')
                    self.wnd.btn_start.setEnabled(True)
                    self.wnd.btn_open_folder.setEnabled(True)
                    return
                # [설명] ocr_data는 KAIT DLL에서 반환된 JSON을 Python 딕셔너리(dict)로 바꾼 결과야.
                ocr_data = self.extract_thread.kait_scan.ocr_data
                # ID_NAME/ID_TYPE 값은 이미지 표시 조건으로 사용하지 않아. OCR 결과 자체는 있어야 해.
                if not ocr_data:
                    self.show_alert('스캔 결과가 없습니다.')
                    self.wnd.btn_start.setEnabled(True)
                    self.wnd.btn_open_folder.setEnabled(True)
                    return
                # ID_IMG1이 없거나 비어 있으면 이미지 표시를 진행하지 않아.
                if 'ID_IMG1' not in ocr_data or not ocr_data['ID_IMG1']:
                    self.show_alert('신분증 이미지가 정상적으로 인식되지 않았습니다. 다시 시도해 주세요.')
                    self.wnd.btn_start.setEnabled(True)
                    self.wnd.btn_open_folder.setEnabled(True)
                    return
                # [설명] base64.b64decode는 텍스트 형태로 전송된 이미지 데이터를 실제 바이트(bytes)로 되돌려.
                image_bytes = base64.b64decode(ocr_data['ID_IMG1'])
                # [설명] QByteArray는 Qt가 처리할 수 있는 바이트 배열이야. 이미지 바이트를 QPixmap에 전달하기 위해 사용해.
                image_bytearray = QByteArray(image_bytes)
                # [설명] QPixmap은 Qt에서 이미지 표시·저장을 담당하는 객체야.
                pixmap = QPixmap()
                # [설명] loadFromData는 메모리에 있는 이미지 바이트로 QPixmap을 만들어.
                pixmap.loadFromData(image_bytearray)
                # [설명] label_img_viewer는 이미지 미리보기 라벨이야. setPixmap으로 표시하고 중앙 정렬·크기 맞춤을 적용해.
                self.wnd.label_img_viewer.setPixmap(pixmap)
                self.wnd.label_img_viewer.setAlignment(QtCore.Qt.AlignCenter)
                self.wnd.label_img_viewer.setScaledContents(True)
                # [설명] 사용자가 저장 폴더를 정했다면 그 폴더에 이미지를 저장해. 같은 이름이 있으면 덮어쓸 수 있어.
                if self.save_folder_path:
                    # [설명] pixmap.save(...'/1.jpg')는 화면에서 사용하는 이미지를 JPEG 파일로 저장해. 여기서는 TWAIN 원본 DIB가 아니라 ID_IMG1 결과야.
                    pixmap.save(self.save_folder_path + '/1.jpg')
                self.wnd.btn_start.setEnabled(True)
                self.wnd.btn_open_folder.setEnabled(True)
            # [설명] Exception as E는 발생한 예외 객체를 E라는 변수로 받아 출력하기 위한 문법이야.
            except Exception as E:
                print(E)
        except Exception as E:
            print(E)
            return


# [설명] [함수: fake] pass만 있는 빈 함수야. 원본 복원 구조를 유지했어.
def fake():
    pass


# [설명] __name__ == '__main__'은 이 파일을 직접 실행했을 때만 아래 코드를 시작한다는 뜻이야.
if __name__ == '__main__':
    # [설명] QApplication은 Qt GUI 앱의 시작점이야. sys.argv는 명령행 인자 목록이야.
    app = QApplication(sys.argv)
    # [설명] apply_stylesheet는 화면 전체에 테마를 적용하는 함수야.
    apply_stylesheet(app, theme='dark_cyan.xml')
    window = ExtractWindow()
    window.show()
    # [설명] app.exec_()는 창의 이벤트 루프를 실행해 클릭과 화면 갱신을 처리하고, 종료 코드를 sys.exit에 전달해.
    sys.exit(app.exec_())
