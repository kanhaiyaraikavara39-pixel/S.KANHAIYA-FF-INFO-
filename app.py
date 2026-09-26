import asyncio
import time
import httpx
import json
import sys
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
from datetime import datetime, timedelta
from google.protobuf import json_format

# =============================================
# PROTO IMPORTS
# =============================================
try:
    import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
    import GetOutfit_pb2
    print("✅ Proto files imported successfully")
except ImportError as e:
    print(f"❌ Proto import error: {e}")
    sys.exit(1)

# =============================================
# CONFIG
# =============================================
RELEASEVERSION = "OB55"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 14; CPH2095 Build/RKQ1.211119.001)"

MAIN_KEY = b'Yg&tc%DEuh6%Zc^8'
MAIN_IV = b'6oyZDr22E3ychjM%'

# =============================================
# JWT TOKEN API
# =============================================
JWT_API_BASE = "https://jwt-wxun.vercel.app/token"

# =============================================
# ACCOUNTS FOR JWT / BOT CREDENTIALS
# (Note: नए बॉट क्रेडेंशियल्स यहाँ अपडेट करें)
# =============================================
ACCOUNT_CREDENTIALS = {
    "BD": {
        "uid": "7909525915", 
        "password": "34C81F9795FBD7C317D56393D08AB0C64CC6301EBBFEB79B15DC248AAC04D410"
    },
    "IND": {
        "uid": "4733343846", 
        "password": "E4896CCA3C5F27787F11D900FAF84F1A2812D19D33B2D4BB11ADEE9AAD48A3DE"
    },
    "BR": {
        "uid": "7909630491",
        "password": "694B9F3007E2C8760664DE3492CA2046FDE7256379820DA8263901204AF4949E"
    },
    "SG": {
        "uid": "YOUR_SG_BOT_UID",        # यहाँ अपने SG बॉट अकाउंट का UID डालें
        "password": "YOUR_SG_BOT_PASSWORD" # यहाँ SG बॉट अकाउंट का पासवर्ड डालें
    }
}

# =============================================
# REGION SERVER CONFIG
# =============================================
REGION_CONFIG = {
    "BD": {"server_url": "https://clientbp.ppmainecoonghj.com", "release_version": RELEASEVERSION},
    "IND": {"server_url": "https://client.ind.freefiremobile.com", "release_version": RELEASEVERSION},
    "BR": {"server_url": "https://client.us.freefiremobile.com", "release_version": RELEASEVERSION},
    "SG": {"server_url": "https://clientbp.ggpolar.com", "release_version": RELEASEVERSION}
}

LOGIN_URLS = {
    "BD": "https://loginbp.ppmainecoonghj.com",
    "IND": "https://loginbp.ppmainecoonghj.com",
    "BR": "https://loginbp.ppmainecoonghj.com",
    "SG": "https://loginbp.ggpolar.com"
}

# === Flask App ===
app = Flask(__name__)
CORS(app)

# =============================================
# In-Memory Token Cache
# =============================================
_token_cache = {}

# =============================================
# JWT Token Function
# =============================================
async def get_jwt_token_from_api(region: str):
    cred = ACCOUNT_CREDENTIALS.get(region)
    if not cred or not cred.get('uid') or "YOUR_" in cred.get('uid'):
        print(f"⚠️ [{region}] Credentials missing or not configured.")
        return None

    url = f"{JWT_API_BASE}?uid={cred['uid']}&password={cred['password']}"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers=headers)
            
            if response.status_code != 200:
                print(f"⚠️ [{region}] JWT API returned {response.status_code}: {response.text[:120]}")
                return None

            data = response.json()
            token = data.get("token")
            if not token:
                print(f"⚠️ [{region}] JWT API returned no token: {data}")
                return None

            api_region = data.get("region", region)
            server_url = REGION_CONFIG.get(api_region, REGION_CONFIG.get(region, {}))["server_url"]

            return {
                "token": f"Bearer {token}",
                "region": api_region,
                "server_url": server_url,
                "expires_at": time.time() + 25200
            }
    except Exception as e:
        print(f"❌ JWT API exception for {region}: {e}")
        return None

# =============================================
# Token Getter (with cache & backup)
# =============================================
async def get_token(region: str):
    cached = _token_cache.get(region)
    if cached and cached.get('expires_at', 0) > time.time():
        return cached

    token_info = await get_jwt_token_from_api(region)

    if not token_info:
        token_info = await generate_token_backup(region)

    if token_info:
        _token_cache[region] = token_info
        return token_info

    print(f"❌ [{region}] Unable to acquire bot token. Account may be banned or API unreachable.")
    return None

async def generate_token_backup(region: str):
    try:
        cred = ACCOUNT_CREDENTIALS.get(region)
        if not cred or not cred.get('uid') or "YOUR_" in cred.get('uid'):
            return None

        account = f"uid={cred['uid']}&password={cred['password']}"

        token_val, open_id = await get_access_token(account)
        if not token_val or not open_id:
            return None

        body = json.dumps({
            "open_id": open_id,
            "open_id_type": "4",
            "login_token": token_val,
            "orign_platform_type": "4"
        })
        proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

        config = REGION_CONFIG.get(region, REGION_CONFIG["BD"])
        login_url = LOGIN_URLS.get(region, LOGIN_URLS["BD"])
        url = f"{login_url}/MajorLogin"

        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': config['release_version']
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, data=payload, headers=headers)
            if resp.status_code != 200:
                print(f"❌ Backup MajorLogin failed for {region}: {resp.status_code}")
                return None

            if b"Exploiting loopholes" in resp.content or b"Modifiers" in resp.content:
                print(f"🚨 [{region}] Bot account (UID: {cred['uid']}) is BANNED by Garena!")
                return None

            try:
                login_res = FreeFire_pb2.LoginRes()
                login_res.ParseFromString(resp.content)
                msg_json = json_format.MessageToJson(login_res)
                msg = json.loads(msg_json)
                if not msg.get("token"):
                    print(f"⚠️ [{region}] MajorLogin returned no token for UID {cred['uid']}")
                    return None
            except Exception as parse_err:
                print(f"⚠️ [{region}] MajorLogin parse error: {parse_err}")
                return None

            return {
                'token': f"Bearer {msg.get('token','0')}",
                'region': msg.get('lockRegion', region),
                'server_url': msg.get('serverUrl', config['server_url']),
                'expires_at': time.time() + 25200
            }
    except Exception as e:
        print(f"❌ Backup token error for {region}: {e}")
        return None

# === Crypto & Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext))

async def json_to_proto(json_data: str, proto_message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Content-Type': "application/x-www-form-urlencoded"}

    for _ in range(2):
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(url, data=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("access_token"), data.get("open_id")
                await asyncio.sleep(1)
        except:
            await asyncio.sleep(1)
    return None, None

# =============================================
# FETCH ACCOUNT INFO FROM GARENA (Direct Region)
# =============================================
async def GetAccountInformation(uid: int, region: str):
    try:
        token_info = await get_token(region)
        if not token_info:
            return {"success": False, "error_type": "NO_TOKEN", "region": region}

        actual_region = token_info.get('region', region)
        token = token_info['token']
        server_url = token_info['server_url']
        config = REGION_CONFIG.get(region, REGION_CONFIG["BD"])

        payload = await json_to_proto(json.dumps({'a': uid, 'b': 7}), main_pb2.GetPlayerPersonalShow())
        data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Authorization': token,
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': config['release_version']
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(server_url + '/GetPlayerPersonalShow', data=data_enc, headers=headers)

            if resp.status_code != 200:
                print(f"⚠️ [{region}] GetPlayerPersonalShow returned {resp.status_code} for UID {uid}")
                if resp.status_code in (401, 429):
                    _token_cache.pop(region, None)
                err_type = "RATE_LIMITED" if resp.status_code == 429 else "NOT_FOUND"
                return {"success": False, "error_type": err_type, "region": region, "status_code": resp.status_code}

            account_info = AccountPersonalShow_pb2.AccountPersonalShowInfo()
            account_info.ParseFromString(resp.content)
            result = json.loads(json_format.MessageToJson(account_info))

            is_banned = result.get("isBanned", False)
            if isinstance(is_banned, bool):
                result["ban_status"] = "🔴 BANNED" if is_banned else "🟢 UNBANNED"
            else:
                result["ban_status"] = "❓ UNKNOWN"

            result["region"] = actual_region
            return {"success": True, "data": result}

    except Exception as e:
        print(f"❌ Error in GetAccountInformation for {region}: {e}")
        return {"success": False, "error_type": "EXCEPTION", "region": region, "error": str(e)}

# =============================================
# FORMATTING HELPERS
# =============================================
def get_item_name(item_id):
    if not item_id or item_id == "0" or item_id == 0:
        return "N/A"
    try:
        import requests
        response = requests.get(f"https://api.danger.workers.dev/item/{item_id}", timeout=3)
        if response.status_code == 200:
            data = response.json()
            return data.get("name", str(item_id))
        return str(item_id)
    except:
        return str(item_id)

def get_rank_name(rp):
    try:
        rp = int(rp)
    except:
        return "N/A"
    if rp == 0: return "Bronze I"
    if rp < 100: return "Bronze II"
    if rp < 200: return "Bronze III"
    if rp < 300: return "Silver I"
    if rp < 400: return "Silver II"
    if rp < 500: return "Silver III"
    if rp < 600: return "Gold I"
    if rp < 700: return "Gold II"
    if rp < 800: return "Gold III"
    if rp < 900: return "Platinum I"
    if rp < 1000: return "Platinum II"
    if rp < 1100: return "Platinum III"
    if rp < 1200: return "Diamond I"
    if rp < 1300: return "Diamond II"
    if rp < 1400: return "Diamond III"
    if rp < 1500: return "Heroic"
    if rp < 2000: return "Master"
    return "Grandmaster"

def ts_to_bst(ts):
    try:
        dt = datetime.fromtimestamp(int(ts)) + timedelta(hours=6)
        return dt.strftime("%d %b %Y at %I:%M:%S %p") + " (BST)"
    except:
        return "N/A"

# =============================================
# MAIN API ROUTE (/player-info)
# =============================================
@app.route('/player-info')
def player_info():
    uid = request.args.get('uid')
    region = (request.args.get('region') or '').strip().upper()

    # 1. वैलिडेशन: UID चेक
    if not uid:
        return jsonify({"status": "error", "message": "Query parameter 'uid' is required."}), 400

    try:
        uid_int = int(uid)
    except:
        return jsonify({"status": "error", "message": "Invalid UID format. UID must be a number."}), 400

    # 2. वैलिडेशन: Region चेक
    if not region:
        return jsonify({"status": "error", "message": "Query parameter 'region' is required (e.g., SG, IND, BD, BR)."}), 400

    if region not in REGION_CONFIG:
        return jsonify({
            "status": "error",
            "message": f"Region '{region}' is not supported. Supported regions: {list(REGION_CONFIG.keys())}"
        }), 400

    # 3. डायरेक्ट उस रीजन के लिए कॉल करें (कोई ऑटो-फ़ॉलबैक नहीं)
    try:
        res = asyncio.run(GetAccountInformation(uid_int, region))
    except Exception as e:
        return jsonify({"status": "error", "message": f"Internal server error: {str(e)}"}), 500

    if not res.get("success"):
        err_type = res.get("error_type")
        if err_type == "NO_TOKEN":
            return jsonify({
                "status": "error",
                "error": f"Bot account for {region} is unavailable or banned.",
                "message": f"Failed to authenticate bot for region {region}. Please update credentials."
            }), 503
        elif err_type == "RATE_LIMITED":
            return jsonify({
                "status": "error",
                "error": "Rate limited by Garena",
                "message": f"Region {region} bot is temporarily rate limited. Please try again shortly."
            }), 429
        else:
            return jsonify({
                "status": "error",
                "message": f"Player not found in region {region} or server returned error."
            }), 404

    account_data = res["data"]
    basic = account_data.get("basicInfo", {})
    clan = account_data.get("clanBasicInfo", {})
    social = account_data.get("socialInfo", {})
    pet = account_data.get("petInfo", {})
    captain = account_data.get("captainBasicInfo", {})
    credit = account_data.get("creditScoreInfo", {})

    prime_level = "N/A"
    try:
        prime_data = basic.get("primeLevel")
        if isinstance(prime_data, dict):
            prime_level = prime_data.get("level", "N/A")
        elif prime_data is not None:
            prime_level = str(prime_data)
    except:
        prime_level = "N/A"

    response = {
        "status": "success",
        "region_queried": region,
        "server_used": account_data.get("region", region),
        "BanStatus": account_data.get("ban_status", "❓ UNKNOWN"),
        "BasicInformation": {
            "PrimeLevel": prime_level,
            "Name": basic.get("nickname", "N/A"),
            "UID": uid,
            "Level": basic.get("level", "N/A"),
            "Exp": basic.get("exp", "N/A"),
            "Region": basic.get("region", "N/A"),
            "Likes": basic.get("liked", "N/A"),
            "HonorScore": credit.get("creditScore", "N/A"),
            "CelebrityStatus": "Yes" if basic.get("showBrRank") else "No",
            "Title": get_item_name(basic.get("title", "0")),
            "Signature": social.get("signature", "N/A")
        },
        "ActivityInformation": {
            "MostRecentOB": basic.get("releaseVersion", "N/A"),
            "BooyahPass": "Yes" if basic.get("hasElitePass") else "No",
            "CurrentBpBadges": basic.get("badgeCnt", "N/A"),
            "BRRank": get_rank_name(basic.get("rankingPoints", 0)),
            "BRPoints": basic.get("rankingPoints", 0),
            "ShowBRRank": "True" if basic.get("showBrRank") else "False",
            "ShowCSRank": "True" if basic.get("showCsRank") else "False",
            "CreatedAt": ts_to_bst(basic.get("createAt", 0)),
            "LastLogin": ts_to_bst(basic.get("lastLoginAt", 0))
        },
        "GuildInformation": {
            "GuildName": clan.get("clanName", "No Guild"),
            "GuildID": clan.get("clanId", "N/A"),
            "GuildLevel": clan.get("clanLevel", "N/A"),
            "LiveMembers": clan.get("memberNum", "N/A"),
            "MaxMembers": clan.get("capacity", "N/A")
        },
        "PetDetails": {
            "Equipped": "Yes" if pet.get("isSelected") else "No",
            "PetNick": pet.get("name", "N/A"),
            "PetType": get_item_name(pet.get("id", "0")),
            "PetSkill": get_item_name(pet.get("selectedSkillId", "0")),
            "PetSkin": get_item_name(pet.get("skinId", "0")),
            "PetExp": pet.get("exp", "N/A"),
            "PetLevel": pet.get("level", "N/A")
        },
        "LeaderInformation": {
            "Name": captain.get("nickname", "N/A"),
            "UID": captain.get("accountId", "N/A"),
            "Level": captain.get("level", "N/A"),
            "Region": captain.get("region", "N/A"),
            "BooyahPass": "Yes" if captain.get("hasElitePass") else "No",
            "CreatedAt": ts_to_bst(captain.get("createAt", 0)),
            "LastLogin": ts_to_bst(captain.get("lastLoginAt", 0)),
            "MostRecentOB": captain.get("releaseVersion", "N/A"),
            "Title": get_item_name(captain.get("title", "0")),
            "BpBadges": captain.get("badgeCnt", "N/A"),
            "BRRank": get_rank_name(captain.get("rankingPoints", 0)),
            "BRPoints": captain.get("rankingPoints", 0)
        }
    }

    return jsonify(response)

@app.route('/')
def home():
    return jsonify({
        "status": "running",
        "version": RELEASEVERSION,
        "endpoint": "/player-info?region=REGION&uid=UID",
        "example": "/player-info?region=SG&uid=338277714",
        "supported_regions": list(REGION_CONFIG.keys())
    })

@app.route('/status')
def token_status():
    status = {}
    for region, info in _token_cache.items():
        expires_in = info['expires_at'] - time.time()
        status[region] = {"has_token": True, "expires_in": f"{expires_in/3600:.1f} hours"}
    return jsonify({"total_tokens": len(_token_cache), "tokens": status})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=False)
