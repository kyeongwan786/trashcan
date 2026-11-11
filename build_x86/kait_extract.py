import ctypes
import json
import os
import glob
import shutil

def clean_json_string(str):
    return ''.join(char for char in str if ord(char) >= 32)

class KaitScan:
    def __init__(self, kait_dll, apiis_dll):
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
            self.kp_err_msg = 'KAIT 모듈이 설치되어 있지 않습니다.'
            return

        if os.path.exists(twlib_path):
            try:
                self.twlib = ctypes.WinDLL(twlib_path)
            except Exception as e:
                print(f"TwLib.dll 로드 실패: {e}")

        # [핵심] IAT 후킹을 통해 TWAIN_GetDib 자동 캡처 설정 적용
        self._setup_twain_hook(kait_dll_path)

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
            return

    def _setup_twain_hook(self, dll_path):
        """KAITIdLib32.dll 내부의 TwLib!TWAIN_GetDib 호출을 가로채는 IAT 후킹"""
        try:
            h_module = self.kait_dll._handle
            
            # PE 헤더 파싱 (32-bit 기준)
            dos_header = h_module
            e_lfanew = ctypes.c_uint.from_address(dos_header + 0x3C).value
            nt_headers = dos_header + e_lfanew
            
            # Optional Header 안의 Import Directory (Data Directory[1])
            optional_header = nt_headers + 0x18
            import_dir_RVA = ctypes.c_uint.from_address(optional_header + 0x80).value
            import_dir = dos_header + import_dir_RVA
            
            original_func_ptr = None
            iat_entry_addr = None
            
            # Import Descriptor 순회
            desc_offset = 0
            while True:
                name_rva = ctypes.c_uint.from_address(import_dir + desc_offset + 12).value
                if name_rva == 0:
                    break
                dll_name = ctypes.c_char_p(dos_header + name_rva).value.decode('utf-8', errors='ignore')
                
                if 'twlib' in dll_name.lower():
                    first_thunk_rva = ctypes.c_uint.from_address(import_dir + desc_offset + 0).value # IAT
                    thunk_data = dos_header + first_thunk_rva
                    
                    idx = 0
                    while True:
                        func_addr_ptr = thunk_data + (idx * 4)
                        func_addr = ctypes.c_uint.from_address(func_addr_ptr).value
                        if func_addr == 0:
                            break
                        
                        # 실제 TwLib의 TWAIN_GetDib 함수 주소와 비교
                        if self.twlib and hasattr(self.twlib, 'TWAIN_GetDib'):
                            target_func = self.twlib.TWAIN_GetDib
                            if func_addr == ctypes.cast(target_func, ctypes.c_void_p).value or True: # 대조 또는 강제 후킹 지점
                                original_func_ptr = func_addr
                                iat_entry_addr = func_addr_ptr
                                break
                        idx = 0x1 # fallback check
                        break
                    if iat_entry_addr:
                        break
                desc_offset += 20

            if iat_entry_addr and original_func_ptr:
                # 후킹 콜백 정의 (WinDbg의 TWAIN_GetDib 반환 직후 동작 모방)
                @ctypes.WINFUNCTYPE(ctypes.c_uint)
                def hooked_twain_get_dib():
                    # 원본 함수 호출하여 핸들(eax) 획득
                    orig_func = ctypes.CFUNCTYPE(ctypes.c_uint, use_last_error=True)(original_func_ptr)
                    handle_val = orig_func()
                    
                    if handle_val:
                        try:
                            # WinDbg의 poi(@eax) 역참조 로직
                            real_ptr = ctypes.c_void_p.from_address(handle_val).value
                            if real_ptr:
                                bi_width = ctypes.c_int.from_address(real_ptr + 4).value
                                bi_height = ctypes.c_int.from_address(real_ptr + 8).value
                                bi_bit_count = ctypes.c_ushort.from_address(real_ptr + 14).value
                                bi_size_image = ctypes.c_uint.from_address(real_ptr + 20).value

                                if bi_size_image == 0:
                                    row_stride = ((bi_width * bi_bit_count + 31) // 32) * 4
                                    bi_size_image = row_stride * abs(bi_height)

                                total_size = max(40 + bi_size_image, 0x1d8828)
                                raw_dib_bytes = ctypes.string_at(real_ptr, total_size)
                                
                                desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
                                dump_path = os.path.join(desktop_path, "front.dib")
                                
                                with open(dump_path, "wb") as f:
                                    f.write(raw_dib_bytes)
                                print(f"[성공] 후킹을 통해 원본 DIB 덤프 완료: {dump_path}")
                        except Exception as e:
                            print(f"후킹 내부 DIB 덤프 에러: {e}")
                            
                    return handle_val

                # 메모리 보호 해제 후 IAT 주소 바꿔치기
                old_protect = ctypes.c_ulong()
                kernel32 = ctypes.windll.kernel32
                kernel32.VirtualProtect(ctypes.c_void_p(iat_entry_addr), 4, 0x40, ctypes.byref(old_protect))
                
                # 콜백 함수 주소 주입
                hook_address = ctypes.cast(hooked_twain_get_dib, ctypes.c_void_p).value
                ctypes.c_uint.from_address(iat_entry_addr).value = hook_address
                
                kernel32.VirtualProtect(ctypes.c_void_p(iat_entry_addr), 4, old_protect, ctypes.byref(old_protect))
                self._hooked_ref = hooked_twain_get_dib # 가비지 컬렉션 방지용 레퍼런스 유지
                
        except Exception as ex:
            print(f"TWAIN Hook 설정 중 예외 (무시 가능): {ex}")

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