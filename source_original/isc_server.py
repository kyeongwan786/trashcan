"""휴지통.exe에 포함된 isc_server 모듈 Python 3.10 bytecode 수동 복원.

Supabase 접속정보는 원본에서도 .env 환경변수에서 가져오는 형태다.
원본 .env/서비스 인증정보는 별도 제공되지 않았다. 정적 분석용 복원본이며
서비스·개인정보가 포함된 실제 서버에 접속해서 테스트하지 말 것.
"""
import os
import sys
import traceback
from dotenv import load_dotenv
from supabase import create_client, Client

extDataDir = os.getcwd()
if getattr(sys, 'frozen', False):
    extDataDir = sys._MEIPASS
load_dotenv(dotenv_path=os.path.join(extDataDir, '.env'))
url: str = os.environ.get('S_U')
url = url.replace('kawergbaz', '')
url = url.replace('abnsdrew', 'supabase')
key: str = os.environ.get('S_K')
key = key.replace('LdWEtrAKjODS', '')
supabase: Client = create_client(url, key)


def get_center_info():
    try:
        center_id = get_center_id()
        if not center_id:
            return None
        response = supabase.table('centers').select('*').eq('id', center_id).execute()
        return response
    finally:
        pass


def get_version_info(program_name):
    try:
        version = get_version(program_name)
        if not version:
            return None
        response = (supabase.table('versions').select('is_deprecated')
                    .eq('version', version).eq('program_name', program_name).execute())
        return response
    finally:
        pass


def get_center_id():
    return os.environ.get('C_I')


def get_version(program_name):
    return os.environ.get(f'{str(program_name).upper()}_VERSION')


def get_extract_info(id_type, name, jumin, issue_date):
    try:
        response = (supabase.table('extracts').select('name')
                    .eq('id_type', id_type).eq('name', name)
                    .eq('jumin', jumin).eq('issue_date', issue_date).execute())
        return response
    finally:
        pass


def upload_id_card(id_type, jumin, file):
    try:
        response = supabase.storage.from_('idcards').upload(
            f'{id_type}/{jumin}', file,
            {'content-type': 'image/jpg', 'x-upsert': 'true'})
        return response
    finally:
        pass


def save_ocr_data(id_type, name, jumin, address, issue_date, issue_place,
                  jumin_back_left, jumin_back_top, jumin_back_right,
                  jumin_back_bottom, uv_ir_tr, kp_no, p_code, valid_msg,
                  license_no=None, program_info={}, scanner_info={}):
    try:
        center_id = get_center_id()
        if not center_id:
            return None
        location_info = get_location_info()
        print(location_info)
        location_info['google_map_url'] = (
            'https://www.google.co.kr/maps/search/'
            f"{location_info.get('location', {}).get('lat')},"
            f"{location_info.get('location', {}).get('lng')}?hl=ko"
        )
        # 원본 bytecode에서 아래 dict는 생성 직후 POP_TOP (사용되지 않음)
        {'program_info': program_info, 'scanner_info': scanner_info}
        # 실제 bytecode는 빈 dict를 insert하는 형태로 남아 있음.
        response = supabase.table('extracts').insert({}).execute()
        return response
    finally:
        pass


def get_location_info():
    location_api_key = os.environ.get('G_L_K')
    location_api_key = location_api_key.replace('QteqIWjEdyXWLDJQu88R', '')
    if not location_api_key:
        return {'error': 'G_L_K 정보가 없습니다.'}
    try:
        import json
        import requests
        url = f'https://www.googleapis.com/geolocation/v1/geolocate?key={location_api_key}'
        data = {'considerIp': True}
        result = requests.post(url, data)
        return json.loads(result.text)
    finally:
        pass


def get_selenium_config_file():
    try:
        response = supabase.storage.from_('extract_config').download('config.txt')
        if response:
            return response.decode('utf-8')
        return None
    finally:
        pass


def download_and_save_file(bucket_name, file_name, save_path):
    try:
        response = supabase.storage.from_(bucket_name).download(file_name)
        if response:
            with open(save_path, 'wb') as file:
                file.write(response)
        print('Failed to download file')
        return False
    finally:
        pass


def get_value_from_config(config_str, key):
    import ast
    try:
        for line in config_str.splitlines():
            if line.strip() and line.startswith(key) and '=' in line:
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip().strip('"')
                if k == key:
                    if v.startswith('[') and v.endswith(']'):
                        return ast.literal_eval(v)
                    if v.lower() in ('true', 'false'):
                        return v.lower() == 'true'
                    if v.startswith('"') and v.endswith('"'):
                        return v[1:-1]
                    return v
                return None
        return None
    finally:
        pass


def save_ad_click_data(blog_addr, ad_title, ad_url, ad_type,
                       search_keyword, site_url, public_ip, version):
    try:
        response = supabase.table('ads').insert({
            'blog_addr': blog_addr, 'ad_title': ad_title, 'ad_url': ad_url,
            'ad_type': ad_type, 'search_keyword': search_keyword,
            'site_url': site_url, 'public_ip': public_ip, 'version': version,
        }).execute()
        return response
    finally:
        pass


def get_prev_ad_click_data(blog_addr, public_ip, start_datetime=None,
                           end_datetime=None, start_range=0, end_range=1000):
    try:
        if start_datetime and end_datetime:
            response = (supabase.table('ads').select('*')
                        .eq('blog_addr', blog_addr).eq('public_ip', public_ip)
                        .gte('clicked_at', str(start_datetime))
                        .lte('clicked_at', str(end_datetime))
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


def get_blog_list():
    try:
        response = supabase.table('blogs').select('*').order('created_at').execute()
        return response
    finally:
        pass


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
        if not response or not response.data:
            return 0
        clicked_ads_cnt += len(response.data)
        if len(response.data) >= 1000:
            clicked_ads_cnt += get_clicked_ads(blog_addr, start_datetime, end_datetime,
                                              start_range + 1000, end_range + 1000)
        return clicked_ads_cnt
    finally:
        pass
