"""휴지통.exe / PYZ-00.pyz 의 kait_extract 모듈 바이트코드 수동 복원.

원본 .py 파일은 아니며, Python 3.10 bytecode에 보존된 함수명·변수명·상수·호출
흐름으로 작성한 읽기용 복원본이다. 실제 DLL 호출은 32-bit Windows에서만 가능하며,
ctypes 함수 반환 타입 선언이 원본에도 없었으므로 실행 검증 없이 사용하지 말 것.
"""
import ctypes
import json
import os


def clean_json_string(str):
    return ''.join(char for char in str if ord(char) >= 32)


class KaitScan:
    def __init__(self, kait_dll, apiis_dll):
        kait_dll_path = r'C:\apps\KAIT\KAITIdLib32.dll'
        self.apiis_dll = apiis_dll
        self.kait_dll = kait_dll
        self.kp_err_msg = None
        if os.path.exists(kait_dll_path):
            self.kait_dll = ctypes.WinDLL(kait_dll_path)
        else:
            self.kp_err_msg = 'KAIT 모듈이 설치되어 있지 않습니다. 설치 후 다시 시도해 주세요.'
            return
        self.telecom_id = 'F3001'
        self.kp_no = None
        self.p_code = None
        result = self.load_kp_code()
        self.err_msg = None
        self.err_code = None
        self.ocr_data = None
        errors = {
            '-1': '공통 모듈 초기화 실패',
            '-2': '사전승낙코드를 읽을 수 없습니다.\n(보안키가 올바로 입력되지 않았거나 MDB 파일읽기 실패)',
            '-5071': '-5071 : Network 에러',
            '-5072': '-5072 : Connection timeout 에러',
            '-5073': '-5073 : HTTP 에러',
            '-5074': '-5074 : Service 포트에 접속에러',
            '-5075': '-5075 : Agent 포트에 접속에러',
            '-5077': '-5077 : JSON Parsing 에러',
            '-5078': '-5078 : 암/복호화 에러',
        }
        if result in errors:
            self.kp_err_msg = errors[result]
            return

    def load_kp_code(self):
        num1 = self.kait_dll.kait_serverstart(0, 0, 3091, 3095, self.telecom_id)
        if num1 != 0:
            return str(num1)
        alloc1 = self.kait_dll.KAIT_JsonToAlloc(0)
        stringUni1 = ctypes.c_wchar_p(alloc1).value
        self.kait_dll.KAIT_JsonToFree(alloc1)
        data1 = json.loads(clean_json_string(stringUni1))
        num2 = data1['ERRCODE']
        if num2 == 0:
            num3 = self.kait_dll.kait_infosel(0, self.telecom_id, 20)
            if num3 != 0:
                return str(num3)
            alloc2 = self.kait_dll.KAIT_JsonToAlloc(0)
            stringUni2 = ctypes.c_wchar_p(alloc2).value
            self.kait_dll.KAIT_JsonToFree(alloc2)
            data2 = json.loads(clean_json_string(stringUni2))
            num4 = data2['ERRCODE']
            if num4 == 0:
                str_val = data2['RET_VAL']
                if str_val is None:
                    return '-2'
                str_val = str_val.split('|')
                print(str_val)
                self.kp_no = str_val[2]
                self.p_code = str_val[1]
                return '0'
            return '-1'
        return '-1'

    def kait_server_start(self):
        retCode = self.kait_dll.kait_serverstart(0, 0, 3091, 3095, self.telecom_id)
        self.err_code = retCode
        if retCode == 0:
            alloc = self.kait_dll.KAIT_JsonToAlloc(0)
            stringUni = ctypes.c_wchar_p(alloc).value
            self.kait_dll.KAIT_JsonToFree(alloc)
            data = json.loads(stringUni)
            retCode = data['ERRCODE']
            errMsg = data['ERRMSG']
            self.err_code = retCode
            self.err_msg = errMsg
            return True
        return False

    def kait_infosel(self):
        retCode = self.kait_dll.kait_infosel(0, self.telecom_id, 2)
        self.err_code = retCode
        if retCode == 0:
            alloc1 = self.kait_dll.KAIT_JsonToAlloc(0)
            stringUni1 = ctypes.c_wchar_p(alloc1).value
            self.kait_dll.KAIT_JsonToFree(alloc1)
            data1 = json.loads(stringUni1)
            retCode, errMsg = data1['ERRCODE'], data1['ERRMSG']
            self.err_code, self.err_msg = retCode, errMsg
            if retCode == 0:
                retCode = self.kait_dll.kait_infoins(0, self.telecom_id, 2, data1['RET_VAL'])
                self.err_code = retCode
                if retCode == 0:
                    alloc2 = self.kait_dll.KAIT_JsonToAlloc(0)
                    stringUni2 = ctypes.c_wchar_p(alloc2).value
                    self.kait_dll.KAIT_JsonToFree(alloc2)
                    data2 = json.loads(stringUni2)
                    retCode, errMsg = data2['ERRCODE'], data2['ERRMSG']
                    self.err_code, self.err_msg = retCode, errMsg
                    return True
                return None
            return False
        return False

    def kait_cryptpwdstr(self):
        nResTmOut = 0
        szPwdVal = '1234'
        szAskVal = '암호화대상 평문'
        retCode = self.kait_dll.kait_cryptpwdstr(nResTmOut, self.telecom_id, szPwdVal, szAskVal)
        self.err_code = retCode
        if retCode == 0:
            alloc = self.kait_dll.KAIT_JsonToAlloc(0)
            stringUni = ctypes.c_wchar_p(alloc).value
            self.kait_dll.KAIT_JsonToFree(alloc)
            data = json.loads(stringUni)
            retCode, errMsg = data['ERRCODE'], data['ERRMSG']
            if data['RET_VAL'] == '':
                retCode = -1
            self.err_code, self.err_msg = retCode, errMsg
            return True
        return False

    def kait_certify(self):
        nResTmOut = 0
        szKaitSvrAddr = 'https://scn.ictmarket.or.kr:8443/'
        szCertCmd = 'IcsmKey/'
        szShopNo = 'P12345'
        szKPNo = self.kp_no
        nScnId = 1001
        szSysVCmd = ('IctClean/IcsmRequest.do' if 'KP' in szKPNo
                     else 'IcsmSvc/IcsmRequestPage')
        retCode = self.kait_dll.kait_certify(
            nResTmOut, self.telecom_id, szKaitSvrAddr, szCertCmd,
            szShopNo, szKPNo, nScnId, szSysVCmd, '', ctypes.c_void_p())
        self.err_code = retCode
        if retCode == 0:
            alloc = self.kait_dll.KAIT_JsonToAlloc(0)
            stringUni = ctypes.c_wchar_p(alloc).value
            print(stringUni)
            self.kait_dll.KAIT_JsonToFree(alloc)
            data = json.loads(stringUni)
            retCode, errMsg = data['ERRCODE'], data['ERRMSG']
            self.err_code, self.err_msg = retCode, errMsg
            return True
        return False

    def kait_onlyidscan(self):
        # 값·인자 순서는 원본 바이트코드와 대조함.
        try:
            nResTmOut, nOcrYn, nTwnDlg, nValiChk = 0, 1, 0, 1
            nScnDpi, nScnBits, nScnSide, nScnRotate = 300, 24, 2, 270
            nSaveFormat, nSaveComp = 2, 64
            szCaption = ''
            THandle = ctypes.c_void_p()
            nScnId = 1001
            retCode = self.kait_dll.kait_onlyidscan(
                nResTmOut, self.telecom_id, nOcrYn, nTwnDlg,
                nValiChk, nScnDpi, nScnBits, nScnSide, nScnRotate,
                nSaveFormat, nSaveComp, szCaption, ctypes.byref(THandle), nScnId)
            self.err_code = retCode
            if retCode == 0:
                alloc = self.kait_dll.KAIT_JsonToAlloc(0)
                stringUni = ctypes.c_wchar_p(alloc).value
                self.kait_dll.KAIT_JsonToFree(alloc)
                data = json.loads(clean_json_string(stringUni))
                retCode, errMsg = data['ERRCODE'], data['ERRMSG']
                if retCode <= 2:
                    retCode = 0
                self.err_code, self.err_msg = retCode, errMsg
                self.ocr_data = data
                return True
            return False
        finally:
            pass

    def check_modules(self, number, module_name):
        result = False
        if number == 1:
            result = self.kait_server_start()
        elif number == 2:
            result = self.kait_infosel()
        elif number == 3:
            result = self.kait_cryptpwdstr()
        elif number == 4:
            result = self.kait_certify()
        elif number == 5:
            result = self.kait_onlyidscan()
        if self.err_code == 0 and result:
            print(f'{module_name} 확인 결과 (OK)')
            return True
        print(f'{module_name} 확인 결과 (ERR)')
        print(f'에러 코드: [{self.err_code}], 에러 메세지: {self.err_msg}')
        return False

    def start_id_scan(self):
        if not (self.check_modules(1, 'MDB,암호화모듈 상태')
                and self.check_modules(4, '유효성검증 요청')
                and self.check_modules(5, '신분증스캐너 동작 상태')):
            return
        print('신분증 스캔 완료')
