import ctypes
import json
import os
import glob
import shutil
import traceback

def show_error_box(title, message):
    try:
        ctypes.windll.user32.MessageBoxW(0, str(message), str(title), 0x10)
    except:
        pass

def clean_json_string(str):
    return ''.join(char for char in str if ord(char) >= 32)

# Windows 예외 처리 구조체 정의 (VEH용)
class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [
        ("ExceptionCode", ctypes.c_ulong),
        ("ExceptionFlags", ctypes.c_ulong),
        ("ExceptionRecord", ctypes.c_void_p),
        ("ExceptionAddress", ctypes.c_void_p),
        ("NumberParameters", ctypes.c_ulong),
        ("ExceptionInformation", ctypes.c_void_p * 15),
    ]

class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_longlong)]

class XSAVE_FORMAT(ctypes.Structure):
    _fields_ = [
        ("ControlWord", ctypes.c_ushort), ("StatusWord", ctypes.c_ushort),
        ("TagWord", ctypes.c_ubyte), ("Reserved1", ctypes.c_ubyte),
        ("ErrorOpcode", ctypes.c_ushort), ("ErrorOffset", ctypes.c_ulong),
        ("ErrorSelector", ctypes.c_ushort), ("Reserved2", ctypes.c_ushort),
        ("DataOffset", ctypes.c_ulong), ("DataSelector", ctypes.c_ushort),
        ("Reserved3", ctypes.c_ushort), ("MxCsr", ctypes.c_ulong), ("MxCsr_Mask", ctypes.c_ulong),
        ("FloatSave", M128A * 8), ("RegMmx", M128A * 8), ("Reserved4", ctypes.c_ulonglong * 16),
        ("Reserved5", ctypes.c_ulonglong)
    ]

class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", ctypes.c_ulong),
        ("Dr0", ctypes.c_ulong), ("Dr1", ctypes.c_ulong), ("Dr2", ctypes.c_ulong),
        ("Dr3", ctypes.c_ulong), ("Dr6", ctypes.c_ulong), ("Dr7", ctypes.c_ulong),
        ("FloatSave", XSAVE_FORMAT),
        ("SegGs", ctypes.c_ulong), ("SegFs", ctypes.c_ulong), ("SegEs", ctypes.c_ulong), ("SegDs", ctypes.c_ulong),
        ("Edi", ctypes.c_ulong), ("Esi", ctypes.c_ulong), ("Ebx", ctypes.c_ulong), ("Edx", ctypes.c_ulong),
        ("Ecx", ctypes.c_ulong), ("Eax", ctypes.c_ulong), ("Ebp", ctypes.c_ulong),
        ("Eip", ctypes.c_ulong), ("SegCs", ctypes.c_ulong), ("EFlags", ctypes.c_ulong),
        ("Esp", ctypes.c_ulong), ("SegSs", ctypes.c_ulong),
        ("ExtendedRegisters", ctypes.byte * 512)
    ]

class EXCEPTION_POINTERS(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
        ("ContextRecord", ctypes.POINTER(CONTEXT))
    ]

# 전역 변수로 브레이크포인트 상태 관리
_bp_info = {
    "addr": 0,
    "orig_byte": 0,
    "hit": False
}

def veh_handler(exception_pointers):
    try:
        rec = exception_pointers.contents.ExceptionRecord.contents
        ctx = exception_pointers.contents.ContextRecord.contents
        
        # EXCEPTION_BREAKPOINT (0x80000003) 확인 및 주소 일치 여부 체크
        if rec.ExceptionCode == 0x80000003 and rec.ExceptionAddress == ctypes.c_void_p(_bp_info["addr"]).value:
            if not _bp_info["hit"]:
                _bp_info["hit"] = True
                
                # WinDbg의 r eax 동작 (EAX 레지스터 값 = DIB 핸들 획득)
                handle_val = ctx.Eax
                if handle_val != 0:
                    try:
                        # WinDbg의 ? poi(@eax) 역참조 동작 (실제 메모리 주소 획득)
                        real_ptr = ctypes.c_void_p.from_address(handle_val).value
                        if real_ptr:
                            # 비트맵 규격 정보 읽기
                            bi_width = ctypes.c_int.from_address(real_ptr + 4).value
                            bi_height = ctypes.c_int.from_address(real_ptr + 8).value
                            bi_bit_count = ctypes.c_ushort.from_address(real_ptr + 14).value
                            bi_size_image = ctypes.c_uint.from_address(real_ptr + 20).value

                            if bi_size_image == 0:
                                row_stride = ((bi_width * bi_bit_count + 31) // 32) * 4
                                bi_size_image = row_stride * abs(bi_height)

                            total_size = max(40 + bi_size_image, 0x1D8828)
                            
                            # 메모리 데이터 통째로 읽기 (.writemem 대용)
                            raw_dib_bytes = ctypes.string_at(real_ptr, total_size)
                            
                            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
                            dump_path = os.path.join(desktop_path, "front.dib")
                            
                            with open(dump_path, "wb") as f:
                                f.write(raw_dib_bytes)
                            
                            show_error_box("DIB 덤프 성공", f"바탕화면에 원본 DIB 저장 완료:\n{dump_path}")
                    except Exception as inner_e:
                        print(f"DIB dump process error: {inner_e}")
                
                # 원래 명령어로 복구 후 EIP를 재조정하여 정상 실행 속개
                kernel32 = ctypes.windll.kernel32
                old_prot = ctypes.c_ulong()
                kernel32.VirtualProtect(ctypes.c_void_p(_bp_info["addr"]), 1, 0x40, ctypes.byref(old_prot))
                ctypes.c_ubyte.from_address(_bp_info["addr"]).value = _bp_info["orig_byte"]
                kernel32.VirtualProtect(ctypes.c_void_p(_bp_info["addr"]), 1, old_prot, ctypes.byref(old_prot))
                
                ctx.Eip -= 1 # 브레이크포인트 명령(0xCC) 지점으로 EIP 되돌림
                ctx.EFlags |= 0x100 # Trap Flag 설정 (단일 스텝 후 재적용용)
                return -1 # EXCEPTION_CONTINUED_EXECUTION (-1)
        
        # 단일 스텝 처리 (다음 명령 실행 후 브레이크포인트 재설치)
        if rec.ExceptionCode == 0x80000004: # EXCEPTION_SINGLE_STEP
            if _bp_info["hit"]:
                kernel32 = ctypes.windll.kernel32
                old_prot = ctypes.c_ulong()
                kernel32.VirtualProtect(ctypes.c_void_p(_bp_info["addr"]), 1, 0x40, ctypes.byref(old_prot))
                ctypes.c_ubyte.from_address(_bp_info["addr"]).value = 0xCC # 다시 0xCC 박기
                kernel32.VirtualProtect(ctypes.c_void_p(_bp_info["addr"]), 1, old_prot, ctypes.byref(old_prot))
                _bp_info["hit"] = False
            return -1
            
    except Exception as ex:
        print(f"VEH exception: {ex}")
    return 0 # EXCEPTION_CONTINUE_SEARCH (0)

class KaitScan:
    def __init__(self, kait_dll, apiis_dll):
        try:
            kait_dll_path = r'C:\apps\KAIT\KAITIdLib32.dll'
            twlib_path = r'C:\apps\KAIT\TwLib.dll'
            
            self.apiis_dll = apiis_dll
            self.kait_dll = None
            self.twlib = None
            self.kp_err_msg = None
            self.current_stage = 'KAIT initialization'
            
            if os.path.exists(kait_dll_path):
                self.kait_dll = ctypes.WinDLL(kait_dll_path)
            else:
                show_error_box("초기화 에러", f"KAIT 모듈을 찾을 수 없습니다: {kait_dll_path}")
                self.kp_err_msg = 'KAIT 모듈이 설치되어 있지 않습니다.'
                return

            if os.path.exists(twlib_path):
                try:
                    self.twlib = ctypes.WinDLL(twlib_path)
                    # [핵심] WinDbg의 bu TwLib!TWAIN_GetDib+0xB 오프셋 브레이크포인트 자동 설정
                    self._setup_breakpoint()
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
                '-2': '사전승낙코드를 읽을 수 없습니다.',
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
                show_error_box("KP 코드 에러", self.kp_err_msg)
                return
        except Exception as init_err:
            show_error_box("__init__ 치명적 에러", traceback.format_exc())

    def _setup_breakpoint(self):
        """WinDbg의 bu TwLib!TWAIN_GetDib+0xB 명령어를 인프로세스 VEH로 완벽 구현"""
        try:
            if not self.twlib:
                return
            
            # TWAIN_GetDib 주소 획득 후 +0xB 오프셋 적용
            get_dib_addr = ctypes.windll.kernel32.GetProcAddress(self.twlib._handle, b"TWAIN_GetDib")
            if not get_dib_addr:
                return
                
            target_addr = get_dib_addr + 0xB
            _bp_info["addr"] = target_addr
            
            # 원래 바이트 백업
            kernel32 = ctypes.windll.kernel32
            old_prot = ctypes.c_ulong()
            kernel32.VirtualProtect(ctypes.c_void_p(target_addr), 1, 0x40, ctypes.byref(old_prot))
            _bp_info["orig_byte"] = ctypes.c_ubyte.from_address(target_addr).value
            
            # 0xCC (INT 3 소프트웨어 브레이크포인트) 주입
            ctypes.c_ubyte.from_address(target_addr).value = 0xCC
            kernel32.VirtualProtect(ctypes.c_void_p(target_addr), 1, old_prot, ctypes.byref(old_prot))
            
            # Vectored Exception Handler 등록
            CMPFUNC = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.POINTER(EXCEPTION_POINTERS))
            self._veh_callback = CMPFUNC(veh_handler)
            kernel32.AddVectoredExceptionHandler(1, self._veh_callback)
            print("WinDbg style TWAIN_GetDib+0xB Breakpoint successfully armed!")
        except Exception as e:
            print(f"Breakpoint setup exception: {e}")

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

    def kait_onlyidScan(self):
        try:
            nResTmOut, nOcrYn, nTwnDlg, nValiChk = 0, 1, 0, 1
            nScnDpi, nScnBits, nScnSide, nScnRotate = 300, 24, 2, 270
            nSaveFormat, nSaveComp = 2, 64
            szCaption = ''
            
            THandle = ctypes.c_void_p()
            nScnId = 1001
            
            retCode = self.kait_dll.kait_onlyidscan(
                nResTmOut, self.telecom_id, nOcrYn, nTwnDlg, nValiChk, 
                nScnDpi, nScnBits, nScnSide, nScnRotate, 
                nSaveFormat, nSaveComp, szCaption, ctypes.byref(THandle), nScnId
            )
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
        except Exception as scan_err:
            show_error_box("kait_onlyidScan 에러", traceback.format_exc())
            return False
        finally:
            pass

    def check_modules(self, number, module_name):
        try:
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
        except Exception as mod_err:
            show_error_box(f"모듈 체크 에러 ({module_name})", traceback.format_exc())
            return False

    def start_id_scan(self):
        try:
            if not (self.check_modules(1, 'MDB,암호화모듈 상태')
                    and self.check_modules(4, '유효성검증 요청')
                    and self.check_modules(5, '신분증스캐너 동작 상태')):
                return
        except Exception as start_err:
            show_error_box("start_id_scan 치명적 에러", traceback.format_exc())