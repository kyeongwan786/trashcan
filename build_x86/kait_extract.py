import ctypes
import json
import os
import glob
import shutil
import traceback
import threading
import time
import struct

def show_error_box(title, message):
    try:
        ctypes.windll.user32.MessageBoxW(0, str(message), str(title), 0x10)
    except:
        pass

def clean_json_string(str):
    return ''.join(char for char in str if ord(char) >= 32)

# ==========================================
# 1. DIB 크기 및 헤더 정밀 검증 로직
# ==========================================

import struct

def calculate_dib_size(header: bytes) -> int:
    if len(header) < 40:
        raise ValueError("DIB 헤더가 40바이트보다 작습니다.")

    (
        bi_size,
        width,
        height,
        planes,
        bit_count,
        compression,
        size_image,
        xppm,
        yppm,
        clr_used,
        clr_important
    ) = struct.unpack_from("<IiiHHIIiiII", header)

    if bi_size != 40:
        raise ValueError(f"지원하지 않는 DIB 헤더: {bi_size}")

    if width <= 0 or height == 0 or planes != 1:
        raise ValueError("잘못된 DIB 이미지 정보")

    if bit_count not in (24, 32):
        raise ValueError(f"지원하지 않는 비트 깊이: {bit_count}")

    if compression != 0:
        raise ValueError(f"지원하지 않는 압축 방식: {compression}")

    if width > 20000 or abs(height) > 20000:
        raise ValueError("비정상적인 이미지 해상도")

    row_stride = ((width * bit_count + 31) // 32) * 4
    pixel_size = row_stride * abs(height)

    if size_image not in (0, pixel_size):
        raise ValueError(
            f"DIB 픽셀 크기 불일치: "
            f"헤더={size_image}, 계산={pixel_size}"
        )

    total_size = bi_size + pixel_size

    if total_size > 100 * 1024 * 1024:
        raise ValueError("DIB 크기가 100MB를 초과합니다.")

    return total_size


# ==========================================
# 2. Windows API 프로토타입 선언 (정확한 인자/반환형)
# ==========================================
kernel32 = ctypes.windll.kernel32

kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
kernel32.OpenProcess.restype = ctypes.c_void_p

kernel32.OpenThread.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
kernel32.OpenThread.restype = ctypes.c_void_p

kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
kernel32.CloseHandle.restype = ctypes.c_int

kernel32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
kernel32.ReadProcessMemory.restype = ctypes.c_int

kernel32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
kernel32.WriteProcessMemory.restype = ctypes.c_int

kernel32.VirtualProtectEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
kernel32.VirtualProtectEx.restype = ctypes.c_int

kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
kernel32.GetProcAddress.restype = ctypes.c_void_p

kernel32.DebugActiveProcess.argtypes = [ctypes.c_ulong]
kernel32.DebugActiveProcess.restype = ctypes.c_int

# [지적 4번 해결] WaitForDebugEvent의 올바른 인자 타입 선언 (DEBUG_EVENT 포인터)
class DEBUG_EVENT(ctypes.Structure):
    pass

kernel32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), ctypes.c_ulong]
kernel32.WaitForDebugEvent.restype = ctypes.c_int

kernel32.ContinueDebugEvent.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
kernel32.ContinueDebugEvent.restype = ctypes.c_int

kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p

kernel32.Process32First.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
kernel32.Process32First.restype = ctypes.c_int

kernel32.Process32Next.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
kernel32.Process32Next.restype = ctypes.c_int

# ==========================================
# 3. 정확한 Windows x86 디버그 및 컨텍스트 구조체 정의
# ==========================================
PROCESS_ALL_ACCESS = 0x1F0FFF
THREAD_ALL_ACCESS = 0x1F03FF
EXCEPTION_BREAKPOINT = 0x80000003
LOAD_DLL_DEBUG_EVENT = 6
EXCEPTION_DEBUG_EVENT = 1
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", ctypes.c_ulong),
        ("cntThreads", ctypes.c_ulong),
        ("th32ParentProcessID", ctypes.c_ulong),
        ("pcPriClassChar", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong),
        ("szExeFile", ctypes.c_char * 260)
    ]

class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [
        ("ExceptionCode", ctypes.c_ulong),
        ("ExceptionFlags", ctypes.c_ulong),
        ("ExceptionRecord", ctypes.c_void_p),
        ("ExceptionAddress", ctypes.c_void_p),
        ("NumberParameters", ctypes.c_ulong),
        ("ExceptionInformation", ctypes.c_void_p * 15)
    ]

class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("FirstChance", ctypes.c_ulong)]

# [지적 3번 해결] 정확한 CREATE_PROCESS_DEBUG_INFO 구조체 필드 정렬

class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", ctypes.c_void_p),
        ("hProcess", ctypes.c_void_p),
        ("hThread", ctypes.c_void_p),
        ("lpBaseOfImage", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", ctypes.c_ulong),
        ("nDebugInfoSize", ctypes.c_ulong),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", ctypes.c_ushort),
    ]


# [지적 2번 해결] 정확한 LOAD_DLL_DEBUG_INFO 구조체 필드 정렬
class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", ctypes.c_void_p),
        ("lpBaseOfImage", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", ctypes.c_ulong),
        ("nDebugInfoSize", ctypes.c_ulong),
        ("lpImageName", ctypes.c_void_p),
        ("Unicode", ctypes.c_ushort)
    ]

class UNION_DEBUG_INFO(ctypes.Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO)
    ]

DEBUG_EVENT._fields_ = [
    ("dwDebugEventCode", ctypes.c_ulong),
    ("dwProcessId", ctypes.c_ulong),
    ("dwThreadId", ctypes.c_ulong),
    ("u", UNION_DEBUG_INFO)
]

# [지적 1번 해결] x86 FLOATING_SAVE_AREA 레이아웃 정확히 반영 (XSAVE_FORMAT 대체)
class FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [
        ("ControlWord", ctypes.c_ulong),
        ("StatusWord", ctypes.c_ulong),
        ("TagWord", ctypes.c_ulong),
        ("ErrorOffset", ctypes.c_ulong),
        ("ErrorSelector", ctypes.c_ulong),
        ("DataOffset", ctypes.c_ulong),
        ("DataSelector", ctypes.c_ulong),
        ("RegisterArea", ctypes.c_byte * 80),
        ("Cr0NpxState", ctypes.c_ulong)
    ]

class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", ctypes.c_ulong),
        ("Dr0", ctypes.c_ulong), ("Dr1", ctypes.c_ulong), ("Dr2", ctypes.c_ulong),
        ("Dr3", ctypes.c_ulong), ("Dr6", ctypes.c_ulong), ("Dr7", ctypes.c_ulong),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", ctypes.c_ulong), ("SegFs", ctypes.c_ulong), ("SegEs", ctypes.c_ulong), ("SegDs", ctypes.c_ulong),
        ("Edi", ctypes.c_ulong), ("Esi", ctypes.c_ulong), ("Ebx", ctypes.c_ulong), ("Edx", ctypes.c_ulong),
        ("Ecx", ctypes.c_ulong), ("Eax", ctypes.c_ulong), ("Ebp", ctypes.c_ulong),
        ("Eip", ctypes.c_ulong), ("SegCs", ctypes.c_ulong), ("EFlags", ctypes.c_ulong),
        ("Esp", ctypes.c_ulong), ("SegSs", ctypes.c_ulong),
        ("ExtendedRegisters", ctypes.c_byte * 512)
    ]

def get_process_id_by_name(process_name):
    snapshot = kernel32.CreateToolhelp32Snapshot(2, 0)
    if snapshot == -1:
        return None
    
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    
    pid = None
    if kernel32.Process32First(snapshot, ctypes.byref(entry)):
        while True:
            if process_name.lower() in entry.szExeFile.decode('utf-8', errors='ignore').lower():
                pid = entry.th32ProcessID
                break
            if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                break
    kernel32.CloseHandle(snapshot)
    return pid


class KaitDebuggerThread(threading.Thread):
    def __init__(self, twlib_path):
        super().__init__()
        self.daemon = True
        self.running = True
        self.twlib_path = twlib_path
        
        local_twlib = ctypes.WinDLL(twlib_path)
        local_func = kernel32.GetProcAddress(local_twlib._handle, b"TWAIN_GetDib")
        self.twlib_rva = local_func - local_twlib._handle
        self.target_bp_addr = 0
        self.orig_byte = 0
        self.scan_count = 0  # 0: 앞면, 1: 뒷면, 2 이상: 추가 스캔분 분기 처리

    def run(self):
        target_pid = None
        while self.running:
            target_pid = get_process_id_by_name("EzSIfSvr.exe")
            if target_pid:
                if kernel32.DebugActiveProcess(target_pid):
                    break
            time.sleep(0.5)

        breakpoint_set = False
        h_process = None
        debug_event = DEBUG_EVENT()
        dll_load_count = 0

        while self.running:
            if not kernel32.WaitForDebugEvent(ctypes.byref(debug_event), 100):
                continue

            continue_status = DBG_CONTINUE

            if debug_event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT:
                dll_load_count += 1
                if not breakpoint_set:
                    try:
                        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, debug_event.dwProcessId)
                        lp_image_name_ptr = debug_event.u.LoadDll.lpImageName
                        is_twlib = False
                        
                        # [지적 7번 해결] 파일 이름 포인터가 없거나 읽을 수 없는 경우(첫 번째 로드 등)에도 대응
                        if lp_image_name_ptr:
                            try:
                                p_str_ptr = ctypes.c_void_p()
                                bytes_rw = ctypes.c_ulong()
                                if kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(lp_image_name_ptr), ctypes.byref(p_str_ptr), ctypes.sizeof(ctypes.c_void_p), ctypes.byref(bytes_rw)):
                                    str_ptr = p_str_ptr.value
                                    if str_ptr:
                                        is_unicode = debug_event.u.LoadDll.Unicode
                                        name_buf = ctypes.create_string_buffer(260)
                                        if kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(str_ptr), name_buf, 260, ctypes.byref(bytes_rw)):
                                            if is_unicode:
                                                filename = ctypes.wstring_from_address(ctypes.addressof(name_buf))
                                            else:
                                                filename = name_buf.value.decode('utf-8', errors='ignore')
                                            if "twlib" in filename.lower():
                                                is_twlib = True
                            except:
                                pass

                        # 만약 이름 확인이 안 되더라도, EzSIfSvr 프로세스 특성상 로드되는 핵심 DLL 순번(예: 3번째 이후)이거나 이름에 twlib가 포함된 경우 확정
                        if is_twlib or dll_load_count >= 3:
                            remote_base = debug_event.u.LoadDll.lpBaseOfImage
                            # [지적 8번 해결] RVA 및 주소 유효성 검사
                            if remote_base:
                                self.target_bp_addr = remote_base + self.twlib_rva + 0xB
                                
                                old_prot = ctypes.c_ulong()
                                if kernel32.VirtualProtectEx(h_process, ctypes.c_void_p(self.target_bp_addr), 1, 0x40, ctypes.byref(old_prot)):
                                    b_orig = ctypes.c_ubyte()
                                    bytes_rw = ctypes.c_ulong()
                                    if kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(self.target_bp_addr), ctypes.byref(b_orig), 1, ctypes.byref(bytes_rw)):
                                        self.orig_byte = b_orig.value
                                        
                                        b_cc = ctypes.c_ubyte(0xCC)
                                        if kernel32.WriteProcessMemory(h_process, ctypes.c_void_p(self.target_bp_addr), ctypes.byref(b_cc), 1, ctypes.byref(bytes_rw)):
                                            kernel32.VirtualProtectEx(h_process, ctypes.c_void_p(self.target_bp_addr), 1, old_prot, ctypes.byref(old_prot))
                                            # [지적 5번 해결] API 성공 여부를 명확히 확인한 후 성공 처리
                                            breakpoint_set = True
                    except Exception as e:
                        print(f"BP setup error: {e}")

            elif debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                ex_code = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                ex_addr = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

                if breakpoint_set and ex_code == EXCEPTION_BREAKPOINT and ex_addr == ctypes.c_void_p(self.target_bp_addr).value:
                    try:
                        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, debug_event.dwThreadId)
                        if h_thread:
                            ctx = CONTEXT()
                            ctx.ContextFlags = 0x10007 # CONTEXT_CONTROL | CONTEXT_INTEGER
                            if kernel32.GetThreadContext(h_thread, ctypes.byref(ctx)):
                                eax_val = ctx.Eax
                                if eax_val != 0:
                                    # 첫 번째 역참조 (poi(@eax))
                                    real_ptr_val = ctypes.c_ulong()
                                    bytes_read = ctypes.c_ulong()
                                    if kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(eax_val), ctypes.byref(real_ptr_val), 4, ctypes.byref(bytes_read)):
                                        real_ptr = real_ptr_val.value
                                        if real_ptr:
                                            # DIB 헤더(40바이트) 읽기
                                            header_buf = (ctypes.c_ubyte * 40)()
                                            if kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(real_ptr), ctypes.byref(header_buf), 40, ctypes.byref(bytes_read)):
                                                header_bytes = bytes(header_buf)
                                                
                                                # [지적 10번 해결] 완벽한 DIB 헤더 검증 및 크기 계산
                                                total_size = calculate_dib_size(header_bytes)
                                                
                                                # [지적 9번 해결] 읽은 바이트 수 엄격 검증
                                                dib_buffer = (ctypes.c_ubyte * total_size)()
                                                actual_read = ctypes.c_ulong(0)
                                                if kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(real_ptr), ctypes.byref(dib_buffer), total_size, ctypes.byref(actual_read)):
                                                    if actual_read.value >= total_size:
                                                        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
                                                        
                                                        # [지적 11, 12번 해결] 세 번째 이상 스캔 시에도 순번별 이름 분기 및 덮어쓰기 방지
                                                        if self.scan_count == 0:
                                                            filename = "front.dib"
                                                        elif self.scan_count == 1:
                                                            filename = "back.dib"
                                                        else:
                                                            filename = f"scan_{self.scan_count + 1}.dib"
                                                            
                                                        dump_path = os.path.join(desktop_path, filename)
                                                        
                                                        with open(dump_path, "wb") as f:
                                                            f.write(bytes(dib_buffer))
                                                        
                                                        show_error_box("DIB 덤프 성공", f"바탕화면에 {filename} 저장 완료! (크기: {total_size} bytes)")
                                                        self.scan_count += 1
                            kernel32.CloseHandle(h_thread)
                    except Exception as ex:
                        print(f"Dump exception: {ex}")

                    # [지적 6번 해결] 중단점 원상 복구 및 EIP 재조정의 완벽한 예외 방어 처리
                    try:
                        old_prot = ctypes.c_ulong()
                        kernel32.VirtualProtectEx(h_process, ctypes.c_void_p(self.target_bp_addr), 1, 0x40, ctypes.byref(old_prot))
                        kernel32.WriteProcessMemory(h_process, ctypes.c_void_p(self.target_bp_addr), ctypes.byref(ctypes.c_ubyte(self.orig_byte)), 1, None)
                        kernel32.VirtualProtectEx(h_process, ctypes.c_void_p(self.target_bp_addr), 1, old_prot, ctypes.byref(old_prot))
                        
                        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, debug_event.dwThreadId)
                        if h_thread:
                            ctx = CONTEXT()
                            ctx.ContextFlags = 0x10002 # CONTEXT_CONTROL
                            kernel32.GetThreadContext(h_thread, ctypes.byref(ctx))
                            ctx.Eip -= 1
                            kernel32.SetThreadContext(h_thread, ctypes.byref(ctx))
                            kernel32.CloseHandle(h_thread)
                    except Exception as rest_err:
                        print(f"Breakpoint restore error: {rest_err}")

                    continue_status = DBG_CONTINUE
                else:
                    # 우리가 관심 없는 예외는 시스템으로 정상 전파
                    continue_status = DBG_EXCEPTION_NOT_HANDLED

            kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)


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
                except Exception as e:
                    print(f"TwLib.dll 로드 실패: {e}")

            self.debugger_thread = KaitDebuggerThread(twlib_path)
            self.debugger_thread.start()

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