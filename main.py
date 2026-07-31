from flask import Flask, request, jsonify
import hmac
import hashlib
import requests
import string
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
import codecs
import time
from datetime import datetime
import urllib3
import base64
import concurrent.futures
import threading
import os
import logging
import re

# ---------- CREDITS ------------------
# t.me/PVT_STAR
# ---------- CREDIT -------------------

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ---------------- KEYS ---------------- #
hex_key = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
key = bytes.fromhex(hex_key)
CLIENT_SECRET_STR = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
AES_IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

REGION_LANG = {"ME": "ar","IND": "hi","ID": "id","VN": "vi","TH": "th","BD": "bn","PK": "ur","TW": "zh","RU": "ru","NA": "en","SAC": "es","BR": "pt"}
REGION_URLS = {
    "IND": "https://client.ind.freefiremobile.com/",
    "ID": "https://clientbp.ggpolarbear.com/",
    "BR": "https://client.us.freefiremobile.com/",
    "ME": "https://clientbp.ggpolarbear.com/",
    "VN": "https://clientbp.ggpolarbear.com/",
    "TH": "https://clientbp.ggpolarbear.com/",
    "RU": "https://clientbp.ggpolarbear.com/",
    "BD": "https://clientbp.ggpolarbear.com/",
    "PK": "https://clientbp.ggpolarbear.com/",
    "SG": "https://clientbp.ggpolarbear.com/",
    "NA": "https://client.us.freefiremobile.com/",
    "SAC": "https://client.us.freefiremobile.com/",
    "EU": "https://clientbp.ggpolarbear.com/",
    "TW": "https://clientbp.ggpolarbear.com/"
}

def get_region(language_code: str) -> str:
    return REGION_LANG.get(language_code)

def get_region_url(region_code: str) -> str:
    return REGION_URLS.get(region_code, None)

thread_local = threading.local()
_proxy_list = []

def set_proxies(proxies):
    global _proxy_list
    _proxy_list = list(proxies)

def get_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        retry_strategy = Retry(total=2, backoff_factor=0.5, status_forcelist=[429,500,502,503,504])
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
        thread_local.session.mount("http://", adapter)
        thread_local.session.mount("https://", adapter)
    if _proxy_list:
        proxy = random.choice(_proxy_list)
        thread_local.session.proxies = {"http": proxy, "https": proxy}
    else:
        thread_local.session.proxies = {}
    return thread_local.session

# ---------------- PROTOBUF ENCODING ---------------- #
def EnC_Vr(N):
    H = []
    while True:
        BesTo = N & 0x7F
        N >>= 7
        if N: BesTo |= 0x80
        H.append(BesTo)
        if not N: break
    return bytes(H)

def CrEaTe_VarianT(field_number, value):
    field_header = (field_number << 3) | 0
    return EnC_Vr(field_header) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value

def CrEaTe_ProTo(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(CrEaTe_LenGTh(field, value))
    return packet

# ---------------- AES ENCRYPTION ---------------- #
def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

# ---------------- JWT ACCOUNT_ID EXTRACTION (from NEW-GENN.py) ---------------- #
def extract_account_id_from_jwt(jwt_token):
    """Extract account_id from JWT token payload - Logic from NEW-GENN.py"""
    try:
        if not jwt_token:
            return None
        
        # Find JWT token in response text (handles extra characters)
        jwt_start = jwt_token.find("eyJ")
        if jwt_start != -1:
            jwt_token = jwt_token[jwt_start:]
        
        # Clean up JWT token
        second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
        if second_dot != -1:
            jwt_token = jwt_token[:second_dot + 44]
        
        # Split JWT token
        parts = jwt_token.split('.')
        if len(parts) >= 2:
            payload_part = parts[1]
            # Add padding if needed
            padding = 4 - len(payload_part) % 4
            if padding != 4:
                payload_part += '=' * padding
            # Decode base64 payload
            decoded = base64.urlsafe_b64decode(payload_part)
            data = json.loads(decoded)
            
            # Try to get account_id or external_id
            account_id = data.get('account_id') or data.get('external_id')
            if account_id:
                return str(account_id)
        
        return None
    except Exception as e:
        logger.error(f"Failed to extract account_id from JWT: {e}")
        return None

# ---------- Password Generation (STAR format) ----------
def generate_hashed_password() -> str:
    prefix = "STAR-"
    suffix = "-CORE"
    characters = string.ascii_uppercase + string.digits
    random_part = ''.join(random.choice(characters) for _ in range(9))
    return f"{prefix}{random_part}{suffix}"

def generate_custom_nickname(name_prefix):
    return name_prefix[:6] + ''.join(random.choices(string.ascii_letters, k=4))

# ---------- Guest Register v2 ----------
def guest_register_v2(password_hash: str) -> str:
    url = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
    payload = {"app_id":100067, "client_type":2, "password":password_hash, "source":2}
    json_body = json.dumps(payload, separators=(',',':'))
    data_to_sign = CLIENT_SECRET_STR + json_body
    signature = hashlib.sha256(data_to_sign.encode()).hexdigest()
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
        "Authorization": f"Signature {signature}",
        "Content-Type": "application/json; charset=utf-8"
    }
    session = get_session()
    resp = session.post(url, data=json_body, headers=headers, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    if data.get("code") != 0:
        raise Exception(f"Guest register failed: {data}")
    return data["data"]["uid"]

def grant_token_v2(uid: str, password_hash: str):
    url = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
    payload = {
        "client_id":100067, "client_secret":CLIENT_SECRET_STR, "client_type":2,
        "password":password_hash, "response_type":"token", "uid":uid
    }
    headers = {"User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)", "Content-Type": "application/json"}
    session = get_session()
    resp = session.post(url, json=payload, headers=headers, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    if data.get("code") != 0:
        raise Exception(f"Token grant failed: {data}")
    return data["data"]["access_token"], data["data"]["open_id"]

# ---------- Encode functions ----------
def encode_string(original):
    keystream = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
    encoded = ""
    for i, ch in enumerate(original):
        encoded += chr(ord(ch) ^ keystream[i % len(keystream)])
    return {"open_id": original, "field_14": encoded}

def to_unicode_escaped(s):
    return ''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in s)

# ---------- MajorRegister ----------
def Major_Regsiter(access_token, open_id, field, uid, password, region, nickname):
    session = get_session()
    url = "https://loginbp.ggpolarbear.com/MajorRegister"
    headers = {
        "Accept-Encoding": "gzip", "Authorization": "Bearer", "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded", "Expect": "100-continue",
        "Host": "loginbp.ggpolarbear.com", "ReleaseVersion": "OB54",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
        "X-GA": "v1 1", "X-Unity-Version": "2018.4.11f1"
    }
    payload = {
        1: nickname, 2: access_token, 3: open_id, 5: 102000007, 6: 4, 7: 1,
        13: 1, 14: field, 15: "en", 16: 2
    }
    payload_hex = CrEaTe_ProTo(payload).hex()
    payload_enc = encrypt_api(payload_hex)
    body = bytes.fromhex(payload_enc)
    response = session.post(url, headers=headers, data=body, verify=False, timeout=30)
    if response.status_code != 200:
        logger.error(f"MajorRegister failed: {response.text[:200]}")
        return None
    return login(uid, password, access_token, open_id, response.content.hex(),
                 response.status_code, nickname, region)

# ---------- Login with JWT extraction and account_id ----------
def login(uid, password, access_token, open_id, response_hex, status_code, name, region, retry_lock=False):
    lang = get_region(region) or "en"
    lang_b = lang.encode("ascii")
    headers = {
        "Accept-Encoding": "gzip", "Authorization": "Bearer", "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded", "Expect": "100-continue",
        "Host": "loginbp.ggpolarbear.com", "ReleaseVersion": "OB54",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
        "X-GA": "v1 1", "X-Unity-Version": "2018.4.11f1"
    }
    payload = b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.123.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02' + lang_b + b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
    data = payload
    data = data.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
    data = data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
    d = encrypt_api(data.hex())
    Final_Payload = bytes.fromhex(d)
    URL = "https://loginbp.ggpolarbear.com/MajorLogin"

    session = get_session()
    RESPONSE = session.post(URL, headers=headers, data=Final_Payload, verify=False, timeout=30)
    if RESPONSE.status_code != 200:
        logger.error(f"MajorLogin failed: {RESPONSE.status_code}")
        return None
    if len(RESPONSE.text) < 10:
        logger.error("MajorLogin response too short")
        return None

    # Extract JWT from response and get account_id
    response_text = RESPONSE.text
    jwt_token = None
    account_id = None

    # Find JWT token in response - clean extraction
    jwt_start = response_text.find("eyJ")
    if jwt_start != -1:
        raw = response_text[jwt_start:]
        dot1 = raw.find(".")
        dot2 = raw.find(".", dot1 + 1) if dot1 > 0 else -1
        if dot2 > 0:
            b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-=")
            end = dot2 + 1
            while end < len(raw) and raw[end] in b64_chars:
                end += 1
            jwt_token = raw[:end]
        account_id = extract_account_id_from_jwt(jwt_token)
    
    if not account_id:
        logger.warning("Could not extract account_id from JWT")
        account_id = "N/A"
    
    # Call ChooseRegion if needed (from NEW-GENN.py logic)
    if not retry_lock:
        try:
            region_code = "RU" if region.upper() == "CIS" else region.upper()
            proto_data = CrEaTe_ProTo({1: region_code})
            encrypted_data = encrypt_api(proto_data.hex())
            choose_payload = bytes.fromhex(encrypted_data)
            choose_headers = {
                'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 12; M2101K7AG Build/SKQ1.210908.001)",
                'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
                'Content-Type': "application/x-www-form-urlencoded", 'Expect': "100-continue",
                'Authorization': f"Bearer {jwt_token}", 'X-Unity-Version': "2018.4.11f1",
                'X-GA': "v1 1", 'ReleaseVersion': "OB54"
            }
            choose_url = "https://loginbp.ggpolarbear.com/ChooseRegion"
            requests.post(choose_url, data=choose_payload, headers=choose_headers, verify=False, timeout=30)
        except Exception as e:
            logger.warning(f"ChooseRegion failed: {e}")
    
    return {
        "uid": uid, 
        "password": password, 
        "name": name, 
        "region": region, 
        "status": "full_login", 
        "stage": "complete",
        "account_id": account_id,
        "jwt_token": jwt_token
    }

# ---------- Main account creation ----------
def create_single_account(args):
    name_prefix, region = args

    for attempt in range(3):
        try:
            logger.info(f"Account attempt {attempt+1} for {region}")
            result = create_acc(region, name_prefix)

            if result and result.get('uid') and result.get('password') and result.get('status') == "full_login":
                return result
        except Exception as e:
            logger.error(f"Attempt {attempt+1} error: {e}")
        time.sleep(0.2)
    return None

def create_acc(region, name_prefix):
    password_hash = generate_hashed_password()
    try:
        uid = guest_register_v2(password_hash)
        access_token, open_id = grant_token_v2(uid, password_hash)
        nickname = generate_custom_nickname(name_prefix)
    except Exception as e:
        logger.error(f"Register/token/nickname failed: {e}")
        return None

    # Encode open_id for field 14
    enc = encode_string(open_id)
    field = codecs.decode(to_unicode_escaped(enc['field_14']), 'unicode_escape').encode('latin1')

    # MajorRegister
    result = Major_Regsiter(access_token, open_id, field, uid, password_hash, region, nickname)
    return result

# ---------------- FLASK API ----------------
@app.route('/gen', methods=['GET'])
def generate_accounts():
    count = request.args.get('count', '1')
    region = request.args.get('region', 'IND')
    name = request.args.get('name', 'STAR')

    # Validate count
    try:
        count = min(15, max(1, int(count)))
    except:
        count = 1

    # Validate region
    region = region.upper()
    if region not in REGION_LANG:
        region = "IND"

    logger.info(f"Creating {count} accounts for region {region} with prefix {name}")

    results = []
    attempts = 0
    max_total = count * 5

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        while len(results) < count and attempts < max_total:

            futures = [
                executor.submit(create_single_account, (name, region))
                for _ in range(min(count - len(results), 5))
            ]

            for future in concurrent.futures.as_completed(futures):
                attempts += 1
                res = future.result()
                if res:
                    results.append(res)

                if len(results) >= count:
                    break

            if len(results) < count:
                time.sleep(0.5)

    # Format response similar to NEW-GENN.py format
    formatted_results = []
    for acc in results:
        formatted_results.append({
            "uid": acc.get("uid"),
            "password": acc.get("password"),
            "name": acc.get("name"),
            "region": acc.get("region"),
            "status": acc.get("status"),
            "stage": acc.get("stage"),
            "account_id": acc.get("account_id", "N/A")
        })

    return jsonify({
        "success": len(results) > 0,
        "total_requested": count,
        "total_created": len(results),
        "accounts": formatted_results,
        "attempts_made": attempts
    })

@app.route('/')
def home():
    return jsonify({
        "message": "FreeFire Account Generator - v2 API (OB54)",
        "usage": "/gen?count=COUNT&region=REGION&name=NAME",
        "max_count": 15,
        "regions": list(REGION_LANG.keys()),
        "features": [
            "Custom nickname prefix",
            "Custom STAR password format",
            "Auto region handling",
            "Concurrent account creation",
            "Account ID extraction from JWT"
        ],
        "credit": "t.me/PVT_STAR"
    })

@app.route('/health')
def health():
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
