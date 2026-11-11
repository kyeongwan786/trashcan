# [공부 안내] 이 파일은 KAITIdLib32.dll의 함수를 호출하는 담당이야.
# [공부 안내] 읽는 순서: KaitScan.__init__ → load_kp_code → start_id_scan → kait_server_start → kait_certify → kait_onlyidscan.
# [공부 안내] 원본 DLL 문서가 없으므로 숫자 인자의 공식 의미는 단정하지 않고 확인된 동작만 설명해.
#
"""휴지통.exe / PYZ-00.pyz 의 kait_extract 모듈 바이트코드 수동 복원.

원본 .py 파일은 아니며, Python 3.10 bytecode에 보존된 함수명·변수명·상수·호출
흐름으로 작성한 읽기용 복원본이다. 실제 DLL 호출은 32-bit Windows에서만 가능하며,
ctypes 함수 반환 타입 선언이 원본에도 없었으므로 실행 검증 없이 사용하지 말 것.
"""
# [설명] ctypes는 Python에서 Windows DLL과 같은 네이티브 라이브러리 함수를 호출하기 위한 도구야.
import ctypes
# [설명] json은 DLL이 돌려준 JSON 문자열을 Python 딕셔너리로 바꿀 때 사용해.
import json
import os


# [설명] [함수: clean_json_string] 문자열에서 제어 문자(유니코드 번호 32 미만)를 제거해 JSON 파싱 오류를 줄이려는 함수야.
def clean_json_string(str):
    # [설명] for char in str은 문자열을 한 글자씩 확인하고, ord(char)는 글자의 숫자 코드값을 가져와. join은 남긴 글자를 이어 붙여.
    return ''.join(char for char in str if ord(char) >= 32)


# [설명] [클래스: KaitScan] KAIT DLL 초기화·인증·스캔 요청을 한 객체에서 관리해. 메인 화면의 ExtractThread가 사용해.
class KaitScan:
    # [설명] __init__은 KaitScan(...) 객체가 만들어질 때 자동으로 실행되는 초기화 함수야. self는 생성된 객체 자신을 뜻해.
    def __init__(self, kait_dll, apiis_dll):
        # [설명] KAITIdLib32.dll의 설치 위치야. 이 경로는 원본 복원 코드에서 고정되어 있어.
        kait_dll_path = r'C:\apps\KAIT\KAITIdLib32.dll'
        # [설명] 전달받은 DLL 정보와 오류 상태를 self 변수에 저장해. self.xxx는 다른 메서드에서도 접근할 수 있어.
        self.apiis_dll = apiis_dll
        self.kait_dll = kait_dll
        self.kp_err_msg = None
        # [설명] DLL 파일이 있는지 검사하고, 있으면 ctypes.WinDLL로 로드해. 없으면 오류 메시지를 기록해.
        if os.path.exists(kait_dll_path):
            self.kait_dll = ctypes.WinDLL(kait_dll_path)
        else:
            self.kp_err_msg = 'KAIT 모듈이 설치되어 있지 않습니다. 설치 후 다시 시도해 주세요.'
            return
        # [설명] telecom_id는 KAIT DLL에 전달하는 고정 문자열이야. 사용자가 지정한 값이 아니라 복원 소스에 적힌 상수야.
        self.telecom_id = 'F3001'
        # [설명] kp_no, p_code는 초기엔 None이고 load_kp_code()에서 조회된 값을 넣어.
        self.kp_no = None
        self.p_code = None
        # [설명] 생성자에서 load_kp_code()를 즉시 실행해 KAIT 모듈에서 번호를 읽어와.
        result = self.load_kp_code()
        self.err_msg = None
        self.err_code = None
        self.ocr_data = None
        # [설명] errors는 에러 코드(문자열)를 사람이 이해할 메시지에 대응시키는 딕셔너리야.
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
        # [설명] if result in errors는 조회한 에러 코드가 미리 정의된 목록 안에 있는지 검사해.
        if result in errors:
            self.kp_err_msg = errors[result]
            return

    # [설명] [함수: load_kp_code] KAIT 서비스를 시작한 후 정보 조회 결과에서 사전승낙번호 등을 읽어 self.kp_no/self.p_code에 저장해.
    def load_kp_code(self):
        # [설명] kait_serverstart는 KAIT 초기화 요청이야. 괄호 안 숫자들은 원본 호출 인자이며 여기서는 의미를 임의 추정하지 않아.
        num1 = self.kait_dll.kait_serverstart(0, 0, 3091, 3095, self.telecom_id)
        # [설명] 반환값 num1이 0이 아니면 실패로 보고 오류 코드를 문자열로 돌려줘.
        if num1 != 0:
            return str(num1)
        # [설명] KAIT_JsonToAlloc는 DLL이 준비한 JSON 메모리의 주소를 얻는 함수야. 포인터 반환 타입 등은 원본 헤더가 없으니 주의해야 해.
        alloc1 = self.kait_dll.KAIT_JsonToAlloc(0)
        # [설명] ctypes.c_wchar_p(...).value는 그 주소의 유니코드 문자열을 Python 문자열로 읽으려는 코드야.
        stringUni1 = ctypes.c_wchar_p(alloc1).value
        # [설명] KAIT_JsonToFree는 DLL에서 할당한 JSON 메모리를 해제해. 읽기 전에 해제하면 안 되므로 순서가 중요해.
        self.kait_dll.KAIT_JsonToFree(alloc1)
        # [설명] json.loads(...)는 텍스트를 딕셔너리 등의 Python 자료형으로 파싱해.
        data1 = json.loads(clean_json_string(stringUni1))
        num2 = data1['ERRCODE']
        if num2 == 0:
            # [설명] kait_infosel(..., 20)은 정보 조회 요청이야. 마지막 번호 20은 원본에서 사용한 구분 인자야.
            num3 = self.kait_dll.kait_infosel(0, self.telecom_id, 20)
            if num3 != 0:
                return str(num3)
            alloc2 = self.kait_dll.KAIT_JsonToAlloc(0)
            stringUni2 = ctypes.c_wchar_p(alloc2).value
            self.kait_dll.KAIT_JsonToFree(alloc2)
            data2 = json.loads(clean_json_string(stringUni2))
            num4 = data2['ERRCODE']
            # [설명] ERRCODE가 0이면 성공 분기로 들어가고, RET_VAL 텍스트를 읽어.
            if num4 == 0:
                str_val = data2['RET_VAL']
                # [설명] RET_VAL이 None이면 내용이 없다고 보고 '-2'라는 오류 코드를 반환해.
                if str_val is None:
                    return '-2'
                # [설명] split('|')는 | 문자를 기준으로 문자열을 나눠 리스트로 만들어. 리스트 번호는 0부터 시작해.
                str_val = str_val.split('|')
                print(str_val)
                # [설명] str_val[2]는 세 번째 항목, str_val[1]은 두 번째 항목이야. 각각 kp_no, p_code에 저장해.
                self.kp_no = str_val[2]
                self.p_code = str_val[1]
                # [설명] '0' 문자열을 반환하는데, 정수 0과는 달라. 호출하는 쪽에서 문자열 에러 코드와 비교하고 있어.
                return '0'
            return '-1'
        return '-1'

    # [설명] [함수: kait_server_start] KAIT 서비스 시작 후 ERRMSG/ERRCODE를 읽어 현재 오류 상태에 기록해.
    def kait_server_start(self):
        retCode = self.kait_dll.kait_serverstart(0, 0, 3091, 3095, self.telecom_id)
        self.err_code = retCode
        if retCode == 0:
            # [설명] DLL에 요청한 다음 JSON 문자열을 받는 과정이 여기서 반복돼. alloc → 문자열 읽기 → Free → json.loads 순서야.
            alloc = self.kait_dll.KAIT_JsonToAlloc(0)
            stringUni = ctypes.c_wchar_p(alloc).value
            self.kait_dll.KAIT_JsonToFree(alloc)
            # [설명] 여기서는 clean_json_string을 거치지 않고 JSON을 바로 파싱해. 원본 복원 흐름을 유지한 거야.
            data = json.loads(stringUni)
            retCode = data['ERRCODE']
            errMsg = data['ERRMSG']
            self.err_code = retCode
            self.err_msg = errMsg
            # [설명] return True는 '이 함수의 처리 루틴을 마쳤다'는 뜻이며, 실제 성공 여부는 self.err_code도 함께 확인해야 해.
            return True
        return False

    # [설명] [함수: kait_infosel] KAIT 정보를 조회해 다시 등록하는 보조 경로야. 메인 스캔 흐름에서 직접 호출되는 함수는 아니야.
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
                # [설명] kait_infoins는 조회한 결과값을 다시 DLL에 전달해 등록하는 호출로 보이지만 정확한 의미는 API 문서 확인이 필요해.
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

    # [설명] [함수: kait_cryptpwdstr] 암호화 문자열 처리 테스트처럼 보이는 보조 함수야. 본문에 고정 예시 값이 있어.
    def kait_cryptpwdstr(self):
        nResTmOut = 0
        # [설명] szPwdVal = '1234'는 복원된 코드의 상수야. 실제 사용자 암호라고 단정하지 않아.
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

    # [설명] [함수: kait_certify] KAIT 인증 요청을 보내고 그 결과 JSON에서 코드와 메시지를 읽어.
    def kait_certify(self):
        nResTmOut = 0
        # [설명] 원본이 사용하는 서버 URL 문자열이야. 주석 추가판은 값을 바꾸거나 외부로 전송하지 않아.
        szKaitSvrAddr = 'https://scn.ictmarket.or.kr:8443/'
        szCertCmd = 'IcsmKey/'
        # [설명] [하드코딩 확인] 여기의 szShopNo는 문자 그대로 'P12345'를 넣어. 하지만 별도로 kp_no/p_code를 동적 조회하는 코드도 존재해.
        szShopNo = 'P12345'
        # [설명] self.kp_no는 앞서 load_kp_code에서 모듈이 반환한 값을 사용해. 따라서 모든 인증값이 고정된 건 아니야.
        szKPNo = self.kp_no
        nScnId = 1001
        # [설명] A if 조건 else B는 한 줄로 쓰는 조건식이야. szKPNo 안에 'KP'가 들어있는지에 따라 요청 경로를 달리해.
        szSysVCmd = ('IctClean/IcsmRequest.do' if 'KP' in szKPNo
                     else 'IcsmSvc/IcsmRequestPage')
        # [설명] DLL의 kait_certify 함수에 필요한 인자를 순서대로 전달해. 여기서 byref 대신 c_void_p()를 넘기는 자리는 원본 복원과 같게 유지해.
        retCode = self.kait_dll.kait_certify(
            nResTmOut, self.telecom_id, szKaitSvrAddr, szCertCmd,
            szShopNo, szKPNo, nScnId, szSysVCmd, '', ctypes.c_void_p())
        # [설명] DLL 함수가 돌려준 코드(retCode)를 상태값에 저장하고, 성공하면 상세 JSON을 읽어.
        self.err_code = retCode
        if retCode == 0:
            alloc = self.kait_dll.KAIT_JsonToAlloc(0)
            stringUni = ctypes.c_wchar_p(alloc).value
            # [설명] print(stringUni)는 인증 응답 전체를 콘솔에 남길 수 있으니 민감한 운영 로그일 수 있어. 주석은 해당 실행을 바꾸지 않아.
            print(stringUni)
            self.kait_dll.KAIT_JsonToFree(alloc)
            data = json.loads(stringUni)
            retCode, errMsg = data['ERRCODE'], data['ERRMSG']
            self.err_code, self.err_msg = retCode, errMsg
            return True
        return False

    # [설명] [함수: kait_onlyidscan] 실제 신분증 스캔을 요청하는 핵심 메서드야. OCR/검증 옵션이 고정된 인자로 들어가.
    def kait_onlyidscan(self):
        # 값·인자 순서는 원본 바이트코드와 대조함.
        try:
            # [설명] 여러 변수를 한 줄에서 동시에 설정해. nOcrYn=1은 OCR 사용, nValiChk=1은 검증 사용을 의미하는 이름으로 보이지만 최종 의미는 DLL 정의를 확인해야 해.
            nResTmOut, nOcrYn, nTwnDlg, nValiChk = 0, 1, 0, 1
            # [설명] 300은 DPI, 24는 비트 수, 2는 양면, 270은 회전각으로 사용한 원본 파라미터야. 정확한 열거형 정의는 DLL 문서가 필요해.
            nScnDpi, nScnBits, nScnSide, nScnRotate = 300, 24, 2, 270
            # [설명] nSaveFormat·nSaveComp도 원본에서 정해진 스캔 출력 형식/압축 설정 인자야. 숫자 2와 64의 정확한 뜻은 추정하지 않아.
            nSaveFormat, nSaveComp = 2, 64
            szCaption = ''
            # [설명] ctypes.c_void_p()는 주소값을 담는 포인터형 변수야. ctypes.byref(THandle)은 이 변수를 DLL이 채우도록 변수의 주소를 전달해.
            THandle = ctypes.c_void_p()
            nScnId = 1001
            # [설명] KAIT DLL에 스캔 요청. 코드는 요청 인자를 순서대로 넘기고 반환된 결과 코드를 검사해.
            retCode = self.kait_dll.kait_onlyidscan(
                nResTmOut, self.telecom_id, nOcrYn, nTwnDlg,
                nValiChk, nScnDpi, nScnBits, nScnSide, nScnRotate,
                nSaveFormat, nSaveComp, szCaption, ctypes.byref(THandle), nScnId)
            self.err_code = retCode
            # [설명] retCode가 0이면 DLL에 마련된 JSON 결과를 읽으러 가.
            if retCode == 0:
                alloc = self.kait_dll.KAIT_JsonToAlloc(0)
                stringUni = ctypes.c_wchar_p(alloc).value
                self.kait_dll.KAIT_JsonToFree(alloc)
                # [설명] JSON 문자열을 Python 자료형으로 바꾸고 ERRCODE/ERRMSG를 읽어.
                data = json.loads(clean_json_string(stringUni))
                retCode, errMsg = data['ERRCODE'], data['ERRMSG']
                # [설명] retCode <= 2를 0으로 취급하는 조건은 복원 원본에서 확인된 로직이야. 1·2의 공식 의미는 확인되지 않았어.
                if retCode <= 2:
                    retCode = 0
                self.err_code, self.err_msg = retCode, errMsg
                # [설명] self.ocr_data에 JSON 전체를 보관해. 메인 창에서 ID_NAME/ID_TYPE/ID_IMG1을 이 딕셔너리에서 읽어.
                self.ocr_data = data
                return True
            return False
        finally:
            pass

    # [설명] [함수: check_modules] 숫자(number)에 따라 어떤 KAIT 동작을 실행할지 선택하고 성공/실패 메시지를 출력해.
    def check_modules(self, number, module_name):
        result = False
        # [설명] if/elif는 여러 조건 중 하나만 실행하는 분기문이야. 1=시작, 2=정보 처리, 3=암호, 4=인증, 5=스캔.
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
        # [설명] 실제 함수 반환값과 self.err_code가 둘 다 성공 상태인지 확인해. and는 두 조건을 모두 만족해야 True야.
        if self.err_code == 0 and result:
            print(f'{module_name} 확인 결과 (OK)')
            return True
        print(f'{module_name} 확인 결과 (ERR)')
        print(f'에러 코드: [{self.err_code}], 에러 메세지: {self.err_msg}')
        return False

    # [설명] [함수: start_id_scan] 메인 스레드가 호출하는 '스캔 전체 순서'야. and로 묶어 앞 단계가 실패하면 다음 단계는 실행하지 않아.
    def start_id_scan(self):
        # [설명] 실행 순서는 1(서비스 시작) → 4(인증) → 5(스캔)이야. 2/3 기능은 정의되어 있어도 여기서는 호출하지 않아.
        if not (self.check_modules(1, 'MDB,암호화모듈 상태')
                and self.check_modules(4, '유효성검증 요청')
                and self.check_modules(5, '신분증스캐너 동작 상태')):
            return
        print('신분증 스캔 완료')
