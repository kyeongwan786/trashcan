# [공부 안내] 이 파일은 .env 설정, Supabase DB/스토리지, 위치 API, 광고 데이터 관련 함수들이야.
# [공부 안내] 함수의 정의와 실제 실행은 달라. 메인 스캔 경로에 모두 연결된 것으로 읽으면 안 돼.
#
"""휴지통.exe에 포함된 isc_server 모듈 Python 3.10 bytecode 수동 복원.

Supabase 접속정보는 원본에서도 .env 환경변수에서 가져오는 형태다.
원본 .env/서비스 인증정보는 별도 제공되지 않았다. 정적 분석용 복원본이며
서비스·개인정보가 포함된 실제 서버에 접속해서 테스트하지 말 것.
"""
# [설명] 이 모듈은 원본에 있던 Supabase/환경변수/위치정보/광고 관련 기능을 포함해. 메인 스캔 코드에서 이 기능 전체가 호출된다는 뜻은 아니야.
import os
import sys
import traceback
# [설명] load_dotenv는 .env 파일에서 KEY=VALUE 형태의 설정을 읽어 환경변수로 제공하는 라이브러리야.
from dotenv import load_dotenv
# [설명] Supabase는 온라인 데이터베이스·파일 저장소 서비스야. create_client는 접속 객체를 만드는 함수야.
from supabase import create_client, Client

# [설명] os.getcwd()는 실행 시점의 현재 작업 폴더를 돌려줘. 이 위치를 설정 파일을 찾는 기준으로 사용해.
extDataDir = os.getcwd()
# [설명] getattr(..., 'frozen', False)는 PyInstaller로 묶여 실행 중인지 확인하는 조건이야.
if getattr(sys, 'frozen', False):
    # [설명] 패키지된 EXE에서는 sys._MEIPASS(압축 해제 임시 위치)를 기준으로 바꿔. .env가 EXE 옆에 있다고 자동 인식하는 구조라고 단정하면 안 돼.
    extDataDir = sys._MEIPASS
# [설명] [환경변수 핵심] 경로의 .env 파일을 읽어. 파일을 복원 ZIP에 포함한 것은 아니야.
load_dotenv(dotenv_path=os.path.join(extDataDir, '.env'))
# [설명] S_U는 서버 URL을 의미하는 환경변수 키 이름이야. os.environ.get은 없으면 None을 반환할 수 있어.
url: str = os.environ.get('S_U')
# [설명] replace(문자열A, 문자열B)는 A 부분을 B로 치환해. 여기 두 줄은 URL의 일부 문자열을 제거·치환하는 처리야.
url = url.replace('kawergbaz', '')
url = url.replace('abnsdrew', 'supabase')
# [설명] S_K는 서버 인증 키 환경변수야. 값 자체를 코드에 직접 적지 않고 환경에서 읽는 방식이야.
key: str = os.environ.get('S_K')
# [설명] 여기서도 특정 문자열을 제거해 키 값을 만들어. .env에 값이 없으면 None.replace 때문에 오류가 날 수 있어.
key = key.replace('LdWEtrAKjODS', '')
# [설명] create_client(url, key)는 Supabase에 접속할 때 사용할 클라이언트 객체를 만들어. 이 코드는 모듈 import 시 실행돼.
supabase: Client = create_client(url, key)


# [설명] [함수: get_center_info] 환경변수의 센터 ID로 centers 테이블에서 해당 행을 조회해.
def get_center_info():
    try:
        # [설명] get_center_id는 아래에 정의된 C_I 환경변수를 읽는 함수야. 없으면 None을 반환해.
        center_id = get_center_id()
        if not center_id:
            return None
        # [설명] table('centers').select('*').eq('id', center_id).execute()는 id가 같은 행을 모두 열 선택으로 조회한다는 뜻이야.
        response = supabase.table('centers').select('*').eq('id', center_id).execute()
        return response
    finally:
        pass


# [설명] [함수: get_version_info] 프로그램 버전 정보를 versions 테이블에서 찾아 구버전 여부(is_deprecated)를 조회해.
def get_version_info(program_name):
    try:
        version = get_version(program_name)
        if not version:
            return None
        # [설명] 여러 줄로 이어진 점(.) 메서드 호출은 Supabase 쿼리 조건을 단계적으로 만드는 방식이야.
        response = (supabase.table('versions').select('is_deprecated')
                    .eq('version', version).eq('program_name', program_name).execute())
        return response
    finally:
        pass


# [설명] [함수: get_center_id] .env에서 불러온 C_I 환경변수 값을 반환해. 없으면 None이야.
def get_center_id():
    return os.environ.get('C_I')


# [설명] [함수: get_version] 프로그램 이름을 대문자로 바꾼 뒤 <이름>_VERSION 환경변수를 읽어.
def get_version(program_name):
    return os.environ.get(f'{str(program_name).upper()}_VERSION')


# [설명] [함수: get_extract_info] extracts 테이블에서 신분증 종류·이름·번호·발급일에 맞는 데이터가 있는지 조회해.
def get_extract_info(id_type, name, jumin, issue_date):
    try:
        # [설명] [개인정보 주의] 아래 조건에는 이름·식별번호·발급일이 쿼리 매개변수로 사용돼. 원본 정의를 보존한 것이며 정상 스캔에서 호출됐다는 증거는 없어.
        response = (supabase.table('extracts').select('name')
                    .eq('id_type', id_type).eq('name', name)
                    .eq('jumin', jumin).eq('issue_date', issue_date).execute())
        return response
    finally:
        pass


# [설명] [함수: upload_id_card] idcards 스토리지 버킷에 파일을 업로드하는 함수야. 이 소스에서 정의되어 있다는 것과 실행되었다는 것은 달라.
def upload_id_card(id_type, jumin, file):
    try:
        # [설명] storage.from_('idcards')는 Supabase 파일 저장소의 idcards 버킷을 뜻해.
        response = supabase.storage.from_('idcards').upload(
            # [설명] f'{id_type}/{jumin}'는 종류/번호 형태의 파일 경로를 만드는 f-string이야.
            f'{id_type}/{jumin}', file,
            # [설명] x-upsert는 동일 경로의 기존 항목이 있을 때 덮어쓰기를 허용하는 설정이야.
            {'content-type': 'image/jpg', 'x-upsert': 'true'})
        return response
    finally:
        pass


# [설명] [함수: save_ocr_data] 여러 OCR·스캔 정보를 인자로 받지만, 복원된 실행 문장은 별도의 일부 처리 후 빈 dict를 저장하는 형태야.
def save_ocr_data(id_type, name, jumin, address, issue_date, issue_place,
                  jumin_back_left, jumin_back_top, jumin_back_right,
                  jumin_back_bottom, uv_ir_tr, kp_no, p_code, valid_msg,
                  # [설명] license_no=None은 인자를 생략할 때 None이 기본값이라는 뜻이야. 빈 딕셔너리 기본값은 변경 가능한 객체라 일반적으로 주의가 필요해.
                  license_no=None, program_info={}, scanner_info={}):
    try:
        # [설명] 환경에서 센터 식별자를 읽고 없으면 바로 반환해.
        center_id = get_center_id()
        if not center_id:
            return None
        # [설명] get_location_info는 Google 위치 API로 위치를 조회하려는 보조 함수야.
        location_info = get_location_info()
        print(location_info)
        # [설명] google_map_url 키를 새로 만들어 좌표를 지도 검색 URL로 바꿔 넣어.
        location_info['google_map_url'] = (
            'https://www.google.co.kr/maps/search/'
            f"{location_info.get('location', {}).get('lat')},"
            f"{location_info.get('location', {}).get('lng')}?hl=ko"
        )
        # [설명] [복원 주의] 아래 중괄호 dict는 만들자마자 버려지는 표현식이야. 원본 바이트코드의 동작 형태를 유지하기 위해 남겨 놓았어.
        # 원본 bytecode에서 아래 dict는 생성 직후 POP_TOP (사용되지 않음)
        {'program_info': program_info, 'scanner_info': scanner_info}
        # [설명] [복원 주의] insert({})는 빈 딕셔너리를 DB에 넣는 형태야. 함수 인자를 DB에 그대로 넣는 코드라고 오해하면 안 돼.
        # 실제 bytecode는 빈 dict를 insert하는 형태로 남아 있음.
        response = supabase.table('extracts').insert({}).execute()
        return response
    finally:
        pass


# [설명] [함수: get_location_info] G_L_K 환경변수의 API 키로 Google Geolocation API에 위치정보를 요청해.
def get_location_info():
    # [설명] G_L_K는 위치 API용 설정값이야. 이 값은 원본 `.env`에서 읽어올 수 있는 형태야.
    location_api_key = os.environ.get('G_L_K')
    # [설명] [주의] None일 경우 replace에서 먼저 예외가 나므로 아래 if not location_api_key만으로 누락값을 처리하지는 못해.
    location_api_key = location_api_key.replace('QteqIWjEdyXWLDJQu88R', '')
    if not location_api_key:
        return {'error': 'G_L_K 정보가 없습니다.'}
    try:
        import json
        import requests
        # [설명] 요청할 Google API 주소를 만들고, considerIp=True로 IP 기반 위치 추정이 가능하도록 설정해.
        url = f'https://www.googleapis.com/geolocation/v1/geolocate?key={location_api_key}'
        data = {'considerIp': True}
        # [설명] requests.post는 HTTP POST 요청을 보내는 함수야. 이 코드 경로가 실행된다면 네트워크 통신이 발생해.
        result = requests.post(url, data)
        return json.loads(result.text)
    finally:
        pass


# [설명] [함수: get_selenium_config_file] Supabase extract_config 저장소에서 config.txt를 다운로드하고 UTF-8 문자열로 반환해.
def get_selenium_config_file():
    try:
        response = supabase.storage.from_('extract_config').download('config.txt')
        if response:
            return response.decode('utf-8')
        return None
    finally:
        pass


# [설명] [함수: download_and_save_file] 지정한 파일을 Supabase에서 다운로드해 로컬 파일로 쓰는 보조 함수야.
def download_and_save_file(bucket_name, file_name, save_path):
    try:
        # [설명] storage.from_(bucket_name).download(file_name)는 지정한 저장소와 파일명을 이용해 다운로드해.
        response = supabase.storage.from_(bucket_name).download(file_name)
        if response:
            # [설명] 'wb'는 바이너리 쓰기 모드야. 이미지·ZIP처럼 텍스트가 아닌 파일도 그대로 저장할 수 있어.
            with open(save_path, 'wb') as file:
                file.write(response)
        # [설명] [복원 주의] 파일 저장 성공 여부와 관계없이 아래 실패 메시지와 False 반환으로 흐르는 코드야. 임의로 수정하지 않았어.
        print('Failed to download file')
        return False
    finally:
        pass


# [설명] [함수: get_value_from_config] 여러 줄 설정 문자열 중 지정한 key=값을 찾아 문자열/리스트/불리언으로 변환해.
def get_value_from_config(config_str, key):
    # [설명] ast.literal_eval은 간단한 Python 리터럴(리스트·숫자 등)을 안전하게 파싱하는 함수야. 임의 코드를 실행하는 eval과 달라.
    import ast
    try:
        # [설명] splitlines()는 문자열을 줄별로 나눠 반복해.
        for line in config_str.splitlines():
            # [설명] 빈 줄이 아니고 key로 시작하며 '=' 문자가 있는 줄만 처리해.
            if line.strip() and line.startswith(key) and '=' in line:
                # [설명] split('=', 1)은 첫 번째 = 기호 한 곳에서만 나눠 키와 값을 얻어.
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip().strip('"')
                if k == key:
                    # [설명] 값이 [ ... ]이면 문자열 대신 리스트 등 Python 리터럴로 변환해 반환해.
                    if v.startswith('[') and v.endswith(']'):
                        return ast.literal_eval(v)
                    # [설명] 'true'/'false'라는 글자를 실제 불리언 True/False로 바꿔.
                    if v.lower() in ('true', 'false'):
                        return v.lower() == 'true'
                    if v.startswith('"') and v.endswith('"'):
                        return v[1:-1]
                    return v
                # [설명] [복원 주의] 이 return None의 들여쓰기 위치 때문에 첫 번째 key 조건을 통과한 줄이 불일치하면 바로 None이 될 수 있어.
                return None
        return None
    finally:
        pass


# [설명] [함수: save_ad_click_data] 광고 클릭 정보 한 건을 ads 테이블에 기록하는 함수야.
def save_ad_click_data(blog_addr, ad_title, ad_url, ad_type,
                       search_keyword, site_url, public_ip, version):
    try:
        # [설명] insert({ ... }).execute()는 딕셔너리의 여러 필드를 온라인 DB에 새 행으로 등록해.
        response = supabase.table('ads').insert({
            'blog_addr': blog_addr, 'ad_title': ad_title, 'ad_url': ad_url,
            'ad_type': ad_type, 'search_keyword': search_keyword,
            'site_url': site_url, 'public_ip': public_ip, 'version': version,
        }).execute()
        return response
    finally:
        pass


# [설명] [함수: get_prev_ad_click_data] 광고 클릭 이력을 시간 범위·IP·페이지 범위로 조회해.
def get_prev_ad_click_data(blog_addr, public_ip, start_datetime=None,
                           end_datetime=None, start_range=0, end_range=1000):
    try:
        # [설명] start_datetime과 end_datetime이 모두 있으면 해당 날짜 조건을 함께 적용해.
        if start_datetime and end_datetime:
            response = (supabase.table('ads').select('*')
                        .eq('blog_addr', blog_addr).eq('public_ip', public_ip)
                        .gte('clicked_at', str(start_datetime))
                        .lte('clicked_at', str(end_datetime))
                        # [설명] range(start_range, end_range)는 DB에서 가져올 결과 행 범위를 지정해. Python의 range 반복문이 아니라 Supabase 쿼리 메서드야.
                        .range(start_range, end_range)
                        .order('clicked_at', desc=False).execute())
            return response
        response = (supabase.table('ads').select('*')
                    .eq('blog_addr', blog_addr).eq('public_ip', public_ip)
                    .range(start_range, end_range)
                    .order('clicked_at', desc=False).execute())
        return response
    finally:
        pass


# [설명] [함수: get_blog_list] blogs 테이블의 목록을 생성일 기준으로 조회해.
def get_blog_list():
    try:
        response = supabase.table('blogs').select('*').order('created_at').execute()
        return response
    finally:
        pass


# [설명] [함수: get_clicked_ads] 광고 클릭 건수를 페이지당 최대 1000개씩 조회하고 누적하는 함수야.
def get_clicked_ads(blog_addr, start_datetime=None, end_datetime=None,
                    start_range=0, end_range=1000):
    clicked_ads_cnt = 0
    try:
        if start_datetime and end_datetime:
            response = (supabase.table('ads').select('blog_addr,clicked_at')
                        .eq('blog_addr', blog_addr)
                        .gte('clicked_at', str(start_datetime))
                        .lte('clicked_at', str(end_datetime))
                        .range(start_range, end_range).execute())
        else:
            response = (supabase.table('ads').select('blog_addr,clicked_at')
                        .eq('blog_addr', blog_addr)
                        .range(start_range, end_range).execute())
        # [설명] response.data가 없으면 빈 결과이므로 0을 반환해.
        if not response or not response.data:
            return 0
        clicked_ads_cnt += len(response.data)
        # [설명] 데이터가 1000개 이상이면 같은 함수를 재귀 호출해 다음 페이지를 가져와. 재귀란 함수가 자기 자신을 다시 부르는 방식이야.
        if len(response.data) >= 1000:
            # [설명] 현재 구간에서 얻은 클릭 수에 다음 구간의 결과를 더해. +=는 누적해서 더하는 연산자야.
            clicked_ads_cnt += get_clicked_ads(blog_addr, start_datetime, end_datetime,
                                              start_range + 1000, end_range + 1000)
        return clicked_ads_cnt
    finally:
        pass
