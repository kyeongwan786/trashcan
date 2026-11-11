import ctypes
import json
import os
import glob
import shutil
import traceback
import sys

# Frida 라이브러리 임포트 (런타임 인스트루멘테이션 후킹용)
try:
    import frida
except ImportError:
    frida = None

def show_error_box(title, message):
    try:
        ctypes.windll.user32.MessageBoxW(0, str(message), str(title), 0x10)
    except:
        pass

def clean_json_string(str):
    return ''.join(char for char in str if ord(char) >= 32)

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

            # [핵심] Frida를 이용한 실시간 TWAIN_GetDib 후킹 설정 (자기 자신 프로세스 어태치)
            self._setup_frida_hook()

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

    def _setup_frida_hook(self):
        """Frida를 통한 TwLib!TWAIN_GetDib 실시간 반환값(eax) 및 메모리 덤프 가로채기"""
        if not frida:
            print("Frida 라이브러리가 설치되어 있지 않습니다. (pip install frida 필요)")
            return

        try:
            # 현재 파이썬 프로세스에 자기 자신을 어태치
            self.frida_session = frida.attach(os.getpid())
            
            # 자바스크립트 기반 후킹 스크립트 작성 (WinDbg의 bu TwLib!TWAIN_GetDib+0xB 및 .writemem 완전 대체)
            script_code = """
            var twlib = Process.findModuleByName("TwLib.dll");
            if (twlib != null) {
                var getDibExport = Module.findExportByName("TwLib.dll", "TWAIN_GetDib");
                if (getDibExport != null) {
                    Interceptor.attach(getDibExport, {
                        onEnter: function(args) {
                            // 함수 진입 시점
                        },
                        onLeave: function(retval) {
                            // retval이 바로 WinDbg의 r eax (DIB 핸들)
                            var handleVal = retval.toInt32();
                            if (handleVal !== 0) {
                                try {
                                    // WinDbg의 ? poi(@eax) 역참조 동작 (포인터 주소 읽기)
                                    var realPtr = Memory.readPointer(ptr(handleVal));
                                    if (!realPtr.isNull()) {
                                        // 비트맵 헤더 정보 읽기 (Width, Height, SizeImage 등)
                                        var biWidth = Memory.readS32(realPtr.add(4));
                                        var biHeight = Memory.readS32(realPtr.add(8));
                                        var biBitCount = Memory.readU16(realPtr.add(14));
                                        var biSizeImage = Memory.readU32(realPtr.add(20));

                                        if (biSizeImage === 0) {
                                            var rowStride = Math.floor((biWidth * biBitCount + 31) / 32) * 4;
                                            biSizeImage = rowStride * Math.abs(biHeight);
                                        }

                                        var totalSize = Math.max(40 + biSizeImage, 0x1d8828);
                                        
                                        // 메모리 영역 통째로 읽어서 파이썬으로 전송 (.writemem 대체)
                                        var dibBytes = Memory.readByteArray(realPtr, totalSize);
                                        send({type: "dump_dib", size: totalSize}, dibBytes);
                                    }
                                } catch (e) {
                                    send({type: "log", msg: "Frida hook error: " + e.message});
                                }
                            }
                        }
                    });
                }
            }
            """
            
            self.frida_script = self.frida_session.create_script(script_code)
            
            def on_message(message, data):
                if message['type'] == 'send':
                    payload = message['payload']
                    if payload.get('type') == 'dump_dib' and data:
                        try:
                            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
                            dump_path = os.path.join(desktop_path, "front.dib")
                            with open(dump_path, "wb") as f:
                                f.write(data)
                            show_error_box("DIB 덤프 성공", f"Frida 후킹을 통해 바탕화면에 원본 DIB 저장 완료:\n{dump_path}")
                        except Exception as fe:
                            print(f"File write error: {fe}")
                    elif payload.get('type') == 'log':
                        print(payload.get('msg'))

            self.frida_script.on('message', on_message)
            self.frida_script.load()
            print("Frida TWAIN_GetDib Hook successfully loaded!")
        except Exception as e:
            print(f"Frida hook setup exception: {e}")

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
            
            # 스캔이 실행되는 동안 Frida 후킹이 TWAIN_GetDib 호출과 반환값(eax)을 실시간으로 낚아챔
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