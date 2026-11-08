# api_server.py — FF BD Direct API
# API call দিলেই account তৈরি + activate একসাথে
# Run: python api_server.py
# Docs: http://localhost:10000/docs

import asyncio
import json
import os
import time
import uuid
import random
import string
import hashlib
import hmac
import warnings
from datetime import datetime
from typing import Optional

warnings.filterwarnings("ignore")

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

import requests
import httpx
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════
REGION = "BD"
LANG   = "bn"

ACCOUNTS_FILE = "squad_accounts.json"
RESULT_FILE   = "login_result.json"

MSDK_APP_VER  = "1.132.9"
MSDK_VER_CODE = "2024010012"
MSDK_UA = f"GarenaMSDK/4.0.42(NX809J ;Android 9;en;US;app {MSDK_APP_VER} {MSDK_VER_CODE};)"
HKEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'

RELEASE_VERSION = "OB55"
UNITY_VERSION   = "2018.4.12f1"
CLIENT_VERSION  = "1.132.9"

LOGIN_HOST  = "loginbp.ppmainecoonghj.com"
CLIENT_HOST = "clientbp.ppmainecoonghj.com"
BD_LOGIN_HOST  = f"https://{LOGIN_HOST}"
BD_CLIENT_HOST = f"https://{CLIENT_HOST}"
BD_MAJOR_LOGIN = f"{BD_LOGIN_HOST}/MajorLogin"

HARDCODED_CONFIG = {
    "region":       REGION,
    "lang":         LANG,
    "country_code": REGION,
    "server_url":   f"{BD_LOGIN_HOST}/",
    "client_url":   f"{BD_CLIENT_HOST}/",
}

# ═══════════════════════════════════════════════════════════
#  CRYPTO HELPERS
# ═══════════════════════════════════════════════════════════
def _gen_sig(payload: str) -> str:
    return hmac.new(HKEY.encode(), payload.encode(), hashlib.sha256).hexdigest()

def _aes_encrypt(data: bytes) -> bytes:
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(data, 16))

def _varint(n: int) -> bytes:
    if n < 0: return b''
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n: b |= 0x80
        out.append(b)
        if not n: break
    return bytes(out)

def _tag(f: int, wt: int) -> bytes: return _varint((f << 3) | wt)
def _f_int(f: int, v: int) -> bytes: return _tag(f, 0) + _varint(v)
def _f_str(f: int, v) -> bytes:
    b = v.encode() if isinstance(v, str) else v
    return _tag(f, 2) + _varint(len(b)) + b

def _proto(fields: dict) -> bytes:
    out = bytearray()
    for f, v in fields.items():
        if isinstance(v, int):   out += _f_int(f, v)
        elif isinstance(v, (str, bytes)): out += _f_str(f, v)
    return bytes(out)

def _first_varint(data: bytes, want: int):
    off = 0
    while off < len(data):
        key = shift = 0
        while True:
            b = data[off]; off += 1
            key |= (b & 0x7F) << shift
            if not (b & 0x80): break
            shift += 7
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v = shift = 0
            while True:
                b = data[off]; off += 1
                v |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
            if fn == want: return v
        elif wt == 2:
            ln = shift = 0
            while True:
                b = data[off]; off += 1
                ln |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
            off += ln
        elif wt == 1: off += 8
        elif wt == 5: off += 4
        else: break
    return None

def _extract_field_bytes(data: bytes, want: int) -> Optional[bytes]:
    """Extract a length-delimited (string/bytes) field by number."""
    off = 0
    while off < len(data):
        key = shift = 0
        while True:
            if off >= len(data): return None
            b = data[off]; off += 1
            key |= (b & 0x7F) << shift
            if not (b & 0x80): break
            shift += 7
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v = shift = 0
            while True:
                if off >= len(data): return None
                b = data[off]; off += 1
                v |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
        elif wt == 2:
            ln = shift = 0
            while True:
                if off >= len(data): return None
                b = data[off]; off += 1
                ln |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
            val = data[off:off+ln]; off += ln
            if fn == want: return val
        elif wt == 1: off += 8
        elif wt == 5: off += 4
        else: return None
    return None

def _parse_majorlogin_res(data: bytes) -> dict:
    """Parse MajorLoginRes fields: 1=account_id, 2=region, 8=token, 10=url."""
    out = {"account_id": None, "region": None, "token": None, "url": None}
    off = 0
    while off < len(data):
        key = shift = 0
        while True:
            if off >= len(data): return out
            b = data[off]; off += 1
            key |= (b & 0x7F) << shift
            if not (b & 0x80): break
            shift += 7
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v = shift = 0
            while True:
                if off >= len(data): return out
                b = data[off]; off += 1
                v |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
            if fn == 1: out["account_id"] = v
        elif wt == 2:
            ln = shift = 0
            while True:
                if off >= len(data): return out
                b = data[off]; off += 1
                ln |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
            val = data[off:off+ln]; off += ln
            if fn == 2:  out["region"] = val.decode('utf-8', 'ignore')
            if fn == 8:  out["token"]  = val.decode('utf-8', 'ignore')
            if fn == 10: out["url"]    = val.decode('utf-8', 'ignore')
        elif wt == 1: off += 8
        elif wt == 5: off += 4
        else: return out
    return out

# ═══════════════════════════════════════════════════════════
#  PASSWORD STASH
# ═══════════════════════════════════════════════════════════
_PW_STASH: dict = {}

# ═══════════════════════════════════════════════════════════
#  STEP 1: GUEST REGISTER
# ═══════════════════════════════════════════════════════════
def guest_register(device_id):
    password = ''.join(random.choices(string.ascii_uppercase + string.digits, k=64))
    body = json.dumps({"app_id": 100067, "client_type": 2,
                       "password": password, "source": 2}, separators=(',', ':'))
    headers = {
        "User-Agent": MSDK_UA,
        "Authorization": f"Signature {_gen_sig(body)}",
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "Host": "100067.connect.garena.com",
        "Connection": "Keep-Alive",
    }
    r = requests.post("https://100067.connect.garena.com/api/v2/oauth/guest:register",
                      headers=headers, data=body, verify=False, timeout=20)
    j = r.json()
    if "data" in j and "uid" in j["data"]:
        uid = str(j["data"]["uid"])
        _PW_STASH[uid] = password
        return uid
    raise Exception(f"guest_register failed: {j}")

# ═══════════════════════════════════════════════════════════
#  STEP 2: GUEST TOKEN
# ═══════════════════════════════════════════════════════════
def guest_token(uid):
    pw = _PW_STASH.get(str(uid))
    if not pw:
        raise Exception("missing password — call guest_register first")
    body = json.dumps({
        "client_id": 100067, "client_secret": HKEY, "client_type": 2,
        "password": pw, "response_type": "token", "uid": int(uid),
    }, separators=(',', ':'))
    headers = {
        "User-Agent": MSDK_UA, "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "Host": "100067.connect.garena.com", "Connection": "Keep-Alive",
    }
    r = requests.post("https://100067.connect.garena.com/api/v2/oauth/guest/token:grant",
                      headers=headers, data=body, verify=False, timeout=20)
    j = r.json()
    if "data" in j and "access_token" in j["data"]:
        d = j["data"]
        return {"access_token": d["access_token"],
                "open_id":      d.get("open_id", ""),
                "platform":     d.get("platform", 4),
                "password":     pw}
    raise Exception(f"guest_token failed: {j}")

# ═══════════════════════════════════════════════════════════
#  STEP 3: PRE-LOGIN (404 expected for new guest)
# ═══════════════════════════════════════════════════════════
def pre_login(access_token, open_id):
    try:
        fields = {
            3:  str(int(time.time())),
            4:  "free fire",
            5:  1,
            7:  CLIENT_VERSION,
            22: open_id,
            23: "4",
            26: "BD",
            29: access_token,
            30: 1,
        }
        payload = _aes_encrypt(_proto(fields))
        headers = {
            "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-GA": "v1 1",
            "ReleaseVersion": RELEASE_VERSION,
            "X-Unity-Version": UNITY_VERSION,
            "Host": LOGIN_HOST,
            "Connection": "Keep-Alive",
            "X-Ga-Sv": str(int(time.time())),
        }
        r = requests.post(BD_MAJOR_LOGIN, data=payload, headers=headers,
                          verify=False, timeout=20)
        return r.status_code in (200, 404)
    except Exception:
        return False

# ═══════════════════════════════════════════════════════════
#  STEP 4: MAJOR REGISTER (account creation)
# ═══════════════════════════════════════════════════════════
FIELD22_HEX = ("47475245010101008202000048d0c6912766f3f72cedb7201cf7a7098d74888b9eb4070aec58e1cd29f26559fb3b8d32cc302d17c00fe629c20b94bece7b75867df5d2c63ad694fe754b06ca5f200fcc316532ee2d705c69d64e873a976d73f1bada85dedb1271bfd90f13e6eb1f607b197ea5741550829c40b5b9ab59f305fd460c462ac2ba9a50561b453053303105b3329e6aef4bf468da4ae276023c26fa39932d0ec40d874a849550e72f67b2f1e0974f835df6a8b5f3cd886483abd0da7cbccc6cd4df72aa5b104e63ea2bfeaf7b08d5176d2a9b128b8630468f625392397e2e43f63969e842f6e2c001c6da1cab2660eacaf8fdbc20520e1316a538406c480f3eefae89171f542b6aa5a8da797673764b0b05ac26a31511759cbdad6826ab621d208e0cf5282a76eb8453f8f768fd8d52dd408d64c0063149605de6af9b34bdf22202ea8d132cd797bbfb6ac72455000c493b18085957df0144f73b36b1aec77f8f5ca3c838d1c2b7e065db59df08b0e8b87dc6769a12ed8ed729c5a3c58468afc6f0c52604a3448b3dbca6a587ccff08bbdcd22e767169949942742142f52f837bfe97f49c801cad0b2d3fd22101188bd5e1dafeeabc4259abe0c7f2b96c5ded89eac5843e7cb95177755b6cf63edd6abaccf03fadcb7084988b2c28d7f3574da8775f6a2de3a429513837ad8319fefa6eb9bfaa1a1a8b06f9d58778c953ab1fc38b4569879416e65625d15ce233cbfffb2cbd56aeb16e07e05da7a52bff20f1d4e11643a328b28105ab74256507f9fccab3bfd0575b4b6fb0fdbeb448c9a1e4e780a4dfdabb2b487cd83f42764816d9a6f3e313349b95ce6fb5ca6dbb60d2f5c3b5157da94c84e2b7ce0e47e5dcbf4d7c146089b104979a5627e4f70a0a8d51a9ce358761119e0eb5ec3d2d7fea4f87227f9dfeaeb3a4ccd2b4cd38caa754c827d45ff0d00d520db11a49fdb6f0b4010203")

KEYSTREAM = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,
             0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]

def major_register(open_id, access_token, nickname):
    encoded = "".join(chr(ord(c) ^ KEYSTREAM[i % len(KEYSTREAM)])
                      for i, c in enumerate(open_id))
    fields = {
        1:  nickname,
        2:  access_token,
        3:  open_id,
        5:  102000007,
        6:  4,
        7:  1,
        8:  4,
        13: 1,
        14: encoded.encode('latin1'),
        15: LANG,
        16: 1,
        20: CLIENT_VERSION,
        21: 1,
        22: bytes.fromhex(FIELD22_HEX),
    }
    proto = _proto(fields)
    payload = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(proto, 16))
    headers = {
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "X-GA-SV": str(int(time.time())),
        "Authorization": "Bearer",
        "X-GA": "v1 1",
        "ReleaseVersion": RELEASE_VERSION,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": UNITY_VERSION,
        "Host": LOGIN_HOST,
        "Connection": "Keep-Alive",
    }
    r = requests.post(f"{BD_LOGIN_HOST}/MajorRegister",
                      data=payload, headers=headers, verify=False, timeout=20)
    if r.status_code != 200:
        raise Exception(f"MajorRegister HTTP {r.status_code}: {r.content[:120]!r}")
    aid = _first_varint(r.content, 3)
    if not aid:
        try:
            txt = r.content.decode("utf-8", "ignore")
        except Exception:
            txt = r.content.hex()[:120]
        raise Exception(f"MajorRegister soft-reject: {txt[:120]}")
    return str(aid)

# ═══════════════════════════════════════════════════════════
#  STEP 5: MAJOR LOGIN (activation — get fresh token)
# ═══════════════════════════════════════════════════════════
async def _activate_via_majorlogin(open_id, access_token, platform):
    """After register, do a fresh MajorLogin to get active session token."""
    client = httpx.AsyncClient(verify=False, timeout=15.0)
    try:
        fields = {
            3:  str(datetime.now())[:-7],
            4:  'free fire',
            5:  '1',
            7:  CLIENT_VERSION,
            8:  'Android OS 12 / API-31',
            11: 'CarrierDataNetwork',
            19: f'Google|{uuid.uuid4()}',
            21: 'en',
            22: open_id,
            23: str(platform),
            25: 'SM-G998B',
            26: 'BD',
            29: access_token,
            30: '1',
            57: '7428b253defc164018c604a1ebbfebdf',
            74: '/data/app/~~6Cw028g_ld-8Z0z2qhrOLA==/com.dts.freefireth-i3wiaEmpx8CbiRVhUMx_ag==/lib/arm64',
            76: '1',
            77: 'b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~6Cw028g_ld-8Z0z2qhrOLA==/com.dts.freefireth-i3wiaEmpx8CbiRVhUMx_ag==/base.apk',
            78: '3', 79: '2', 81: '64', 83: '2019121229', 85: '3',
            86: 'OpenGLES2', 87: '8191', 88: str(platform),
            93: 'android',
            97: '1', 98: '1', 99: str(platform), 100: str(platform),
            103: '1', 105: '1',
            107: '1.3fb8adbf45f44ce9',
        }
        payload = _aes_encrypt(_proto(fields))
        headers = {
            "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Unity-Version": UNITY_VERSION,
            "X-GA": "v1 1",
            "ReleaseVersion": RELEASE_VERSION,
            "Host": LOGIN_HOST,
        }
        r = await client.post(BD_MAJOR_LOGIN, headers=headers, data=payload)
        if r.status_code != 200:
            return {"success": False, "error": f"MajorLogin HTTP {r.status_code}"}

        res = _parse_majorlogin_res(r.content)
        return {
            "success":     True,
            "account_id":  res["account_id"],
            "region":      res["region"] or "BD",
            "jwt_token":   res["token"],
            "server_url":  res["url"],
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        await client.aclose()

# ═══════════════════════════════════════════════════════════
#  FILE HELPERS
# ═══════════════════════════════════════════════════════════
def _load_json_list(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []

def _save_json_list(path, accounts):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(accounts, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)

# ═══════════════════════════════════════════════════════════
#  CORE: MAKE + ACTIVATE (একসাথে)
# ═══════════════════════════════════════════════════════════
def _generate_nickname(custom_name: Optional[str]) -> str:
    if custom_name and custom_name.strip():
        return custom_name.strip()
    rand = "".join(random.choices("¹²³⁴⁵⁶⁷⁸⁹⁰", k=5))
    return f"AX-ROM{rand}"

async def make_and_activate(custom_name: Optional[str] = None) -> dict:
    device_id = "02-" + str(uuid.uuid4())

    # Step 1: Register guest → get UID + password
    uid = await asyncio.to_thread(guest_register, device_id)
    password = _PW_STASH.get(uid, "")

    # Step 2: Get access token
    tokens = await asyncio.to_thread(guest_token, uid)
    open_id = tokens["open_id"]
    access_token = tokens["access_token"]
    platform = int(tokens.get("platform", 4) or 4)

    # Step 3: Nickname
    nickname = _generate_nickname(custom_name)

    # Step 4: Pre-login (expected 404 for new guest)
    await asyncio.to_thread(pre_login, access_token, open_id)

    # Step 5: Register the account
    account_id = await asyncio.to_thread(major_register, open_id,
                                         access_token, nickname)

    # Step 6: Activate — fresh MajorLogin to get active JWT session
    activation = await _activate_via_majorlogin(open_id, access_token, platform)

    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Save generated account
    acc_record = {
        "uid":          uid,
        "pass":         password,
        "account_id":   account_id,
        "name":         nickname,
        "open_id":      open_id,
        "access_token": access_token,
        "platform":     platform,
        "region":       REGION,
        "created_at":   created_at,
    }
    accounts = _load_json_list(ACCOUNTS_FILE)
    accounts.append(acc_record)
    _save_json_list(ACCOUNTS_FILE, accounts)

    # Save activation result
    if activation.get("success"):
        result_record = {
            "uid":         int(uid),
            "password":    password,
            "account_id":  activation.get("account_id") or int(account_id),
            "name":        nickname,
            "open_id":     open_id,
            "access_token": access_token,
            "jwt_token":   activation.get("jwt_token"),
            "server_url":  activation.get("server_url"),
            "region":      activation.get("region", "BD"),
            "active_status": "SUCCESS",
            "created_at":  created_at,
        }
        results = _load_json_list(RESULT_FILE)
        results.append(result_record)
        _save_json_list(RESULT_FILE, results)

    return {
        "uid":          uid,
        "password":     password,
        "account_id":   account_id,
        "name":         nickname,
        "open_id":      open_id,
        "access_token": access_token,
        "platform":     platform,
        "region":       REGION,
        "created_at":   created_at,
        "activation":   activation,
    }

# ═══════════════════════════════════════════════════════════
#  FASTAPI APP
# ═══════════════════════════════════════════════════════════
app = FastAPI(
    title="FF BD Direct API",
    description="Account create + activate in one call",
    version="2.0.0",
)

@app.get("/")
async def root():
    return {
        "service": "FF BD Direct API",
        "status":  "running",
        "endpoints": {
            "make_account": "/make_account?server=BD&name=AX-ROM",
            "accounts":     "/accounts",
            "results":      "/results",
        },
    }

@app.get("/make_account")
async def api_make_account(
    server: str = Query("BD", description="Server region (BD only)"),
    name: Optional[str] = Query(None, description="Custom nickname (optional)"),
):
    if server.upper() != "BD":
        raise HTTPException(status_code=400, detail="Only server=BD is supported")

    try:
        result = await make_and_activate(custom_name=name)
        act = result.pop("activation", {})
        return JSONResponse({
            "success": True,
            "server": "BD",
            "account": result,
            "activation": {
                "active_status": "SUCCESS" if act.get("success") else "FAILED",
                "jwt_token":     act.get("jwt_token"),
                "server_url":    act.get("server_url"),
                "error":         act.get("error"),
            },
        })
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)},
        )

@app.get("/accounts")
async def api_accounts():
    accs = _load_json_list(ACCOUNTS_FILE)
    return {"count": len(accs), "accounts": accs}

@app.get("/results")
async def api_results():
    res = _load_json_list(RESULT_FILE)
    return {"count": len(res), "results": res}

# ═══════════════════════════════════════════════════════════
#  RUN
# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("  FF BD Direct API — running")
    print("  URL : http://localhost:10000")
    print("  Docs: http://localhost:10000/docs")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=10000)