# ctypes는 Python에서 Windows DLL과 같은 네이티브 라이브러리 함수를 호출
import ctypes

# json은 DLL이 돌려준 JSON 문자열을 Python 딕셔너리로 바꿀 때 사용
import json
import os
import glob
import shutil

# 문자열에서 제어 문자(유니코드 번호 32 미만)를 제거해 JSON 파싱 오류를 줄이려는 함수
def clean_json_string(str):
    return ''.join(char for char in str if ord(char) >= 32)

# KAIT DLL 초기화 인증 스캔 요청을 한 객체에서 관리. 메인화면의 ExtractThread가 사용
class KaitScan:
    def __init__(self, kait_dll, apiis_dll):
        kait_dll_path = r'C:\apps\KAIT\KAITIdLib32.dll'
        twlib_path = r'C:\apps\KAIT\TwLib.dll' # 같은 폴더 내 TwLib.dll 경로
        
        self.apiis_dll = apiis_dll
        self.kait_dll = kait_dll
        self.twlib = None
        self.kp_err_msg = None
        self.current_stage = 'KAIT initialization'
        
        # KAITIdLib32.dll 로드
        if os.path.exists(kait_dll_path):
            self.kait_dll = ctypes.WinDLL(kait_dll_path)
        else:
            self.kp_err_msg = 'KAIT 모듈이 설치되어 있지 않습니다. 설치 후 다시 시도해 주세요.'
            return

        # TwLib.dll 로드 (DIB 핸들을 직접 다루는 핵심 라이브러리)
        if os.path.exists(twlib_path):
            try:
                self.twlib = ctypes.WinDLL(twlib_path)
            except Exception as e:
                print(f"TwLib.dll 로드 실패: {e}")

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
        retCode = self.kait_dll.kait_cryptpwdstr(nResTmOut, self, self.telecom_id, szPwdVal, szAskVal)
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
        szSysVCmd = ('IctClean/IcsmRequest.do' if 'KP' in szKPNo else 'IcsmSvc/IcsmRequestPage')
        retCode = self.kait_dll.kait_certify(
            nResTmOut, self.telecom_id, szKaitSvrAddr, szCertCmd,
            szShopNo, szKPNo, nScnId, szSysVCmd, '', ctypes.c_void_p())
        self.err_code = retCode
        if retCode == 0:
            alloc = self.kait_dll.KAIT_JsonToAlloc(0)
            stringUni = ctypes.c_wchar_p(alloc).value
            self.kait_dll.KAIT_JsonToFree(alloc)
            data = json.loads(clean_json_string(stringUni))
            retCode, errMsg = data['ERRCODE'], data['ERRMSG']
            self.err_code, self.err_msg = retCode, errMsg
            return True
        return False

    # 실제 신분증 스캔을 요청하는 핵심 메서드 (TwLib 연동 및 DIB 덤프 기능 포함)
    def kait_onlyidScan(self):
        def write_debug(msg):
            try:
                with open(r"C:\kait_debug.txt", "a", encoding="utf-8") as f:
                    f.write(msg + "\n")
            except Exception as e:
                print(f"Log error: {e}")

        write_debug("=== [1] kait_onlyidScan 함수 진입 ===")

        try:
            nResTmOut, nOcrYn, nTwnDlg, nValiChk = 0, 1, 0, 1
            nScnDpi, nScnBits, nScnSide, nScnRotate = 300, 24, 2, 270
            nSaveFormat, nSaveComp = 2, 64
            szCaption = ''
            
            THandle = ctypes.c_void_p()
            nScnId = 1001
            
            write_debug("=== [2] kait_onlyidscan DLL 함수 호출 직전 ===")

            retCode = self.kait_dll.kait_onlyidscan(
                nResTmOut, self.telecom_id, nOcrYn, nTwnDlg, nValiChk, 
                nScnDpi, nScnBits, nScnSide, nScnRotate, 
                nSaveFormat, nSaveComp, szCaption, ctypes.byref(THandle), nScnId
            )
            self.err_code = retCode
            write_debug(f"=== [3] kait_onlyidscan 호출 완료. retCode = {retCode} ===")
            
            if retCode == 0:
                # ==========================================================
                # [핵심] TwLib를 통한 원본 DIB 핸들 획득 및 .writemem 방식 구현
                # WinDbg 명령어 순서 반영:
                # 1. TWAIN_GetDib 호출 또는 TwLib 내보내기 함수 활용
                # 2. 핸들 값 획득 -> poi(@eax) 역참조 -> 지정 크기만큼 덤프
                # ==========================================================
                try:
                    if self.twlib and hasattr(self.twlib, 'TWAIN_GetDib'):
                        # WinDbg의 TWAIN_GetDib 함수 직접 호출
                        # 반환값이 핸들(eax)에 해당함
                        dib_handle = self.twlib.TWAIN_GetDib()
                        write_debug(f"=== [4] TWAIN_GetDib 리턴 핸들 값: {hex(dib_handle) if dib_handle else 'None'} ===")
                        
                        if dib_handle:
                            # WinDbg의 poi(@eax) 로직: 핸들이 가리키는 실제 메모리 포인터(CANDIDATE) 주소 읽기
                            real_ptr = ctypes.c_void_p.from_address(dib_handle).value
                            write_debug(f"=== [5] 역참조된 실제 메모리 주소(poi): {hex(real_ptr) if real_ptr else 'None'} ===")
                            
                            if real_ptr:
                                # WinDbg에서 지정했던 크기 (0x1d8828 바이트 또는 헤더 동적 계산)
                                # 유연하게 동적 계산 혹은 고정 크기 적용
                                bi_width = ctypes.c_int.from_address(real_ptr + 4).value
                                bi_height = ctypes.c_int.from_address(real_ptr + 8).value
                                bi_bit_count = ctypes.c_ushort.from_address(real_ptr + 14).value
                                bi_size_image = ctypes.c_uint.from_address(real_ptr + 20).value

                                if bi_size_image == 0:
                                    row_stride = ((bi_width * bi_bit_count + 31) // 32) * 4
                                    bi_size_image = row_stride * abs(bi_height)

                                total_size = max(40 + bi_size_image, 0x1d8828)
                                
                                # 메모리에서 바이트 긁기 (.writemem 대체)
                                raw_dib_bytes = ctypes.string_at(real_ptr, total_size)
                                
                                desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
                                dump_path = os.path.join(desktop_path, "front.dib")
                                
                                with open(dump_path, "wb") as f:
                                    f.write(raw_dib_bytes)
                                write_debug(f"=== [성공] WinDbg 방식 그대로 DIB 덤프 완료: {dump_path} ===")
                    else:
                        write_debug("=== [안내] TwLib에 TWAIN_GetDib 함수가 export되어 있지 않거나 로드되지 않음 ===")
                except Exception as dib_err:
                    import traceback
                    write_debug(f"=== [예외 발생] DIB 덤프 중 에러 ===\n{traceback.format_exc()}")
                # ==========================================================

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
                
            else:
                write_debug(f"=== [실패] 스캔 리턴 코드가 0이 아님: {retCode} ===")
            return False
        except Exception as main_err:
            import traceback
            write_debug(f"=== [치명적 예외] ===\n{traceback.format_exc()}")
            return False
        finally:
            pass

    def check_modules(self, number, module_name):
        self.current_stage = module_name
        result = False
        if number == 1:
            result = self.kait_server_start()
        elif number == 2:
            result = self.kait_infosel()
        elif number == 3:
            result = self
        elif number == 4:
            result = self.kait_certify()
        elif number == 5:
            result = self.kait_onlyidScan()
        if self.err_code == 0 and result:
            return True
        if not self.err_msg:
            self.err_msg = f'{module_name} failed with code {self.err_code!r}'
        return False

    def start_id_scan(self):
        if not (self.check_modules(1, 'MDB,암호화모듈 상태')
                and self.check_modules(4, '유효성검증 요청')
                and self.check_modules(5, '신분증스캐너 동작 상태')):
            return