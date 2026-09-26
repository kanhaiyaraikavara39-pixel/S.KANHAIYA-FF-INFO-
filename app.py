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
# CONFIG (ONLY FOR INDIA / IND SERVER)
# =============================================
RELEASEVERSION = "OB55"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 14; CPH2095 Build/RKQ1.211119.001)"

MAIN_KEY = b'Yg&tc%DEuh6%Zc^8'
MAIN_IV = b'6oyZDr22E3ychjM%'

# आपकी नई JWT API
JWT_API_BASE = "https://ob-55-jwt-two.vercel.app/token"

# आपके द्वारा दिए गए IND बॉट क्रेडेंशियल्स
IND_BOT_CREDS = {
    "uid": "7916211664",
    "password": "9E1218FC47D117D8E9A5F09D4A11B52124990F99487DE2A97FD169C2D48E0759"
}

# केवल IND सर्वर URL कॉन्फ़िगरेशन
IND_SERVER_URL = "https://client.ind.freefiremobile.com"
IND_LOGIN_URL = "https://loginbp.ppmainecoonghj.com"

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
async def get_jwt_token_from_api():
    url = f"{JWT_API_BASE}?uid={IND_BOT_CREDS['uid']}&password={IND_BOT_CREDS['password']}"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers=headers)
            
            if response.status_code != 200:
                print(f"⚠️ JWT API returned {response.status_code}: {response.text[:120]}")
                return None

            data = response.json()
            token = data.get("token")
            if not token:
                print(f"⚠️ JWT API returned no token: {data}")
                return None

            return {
                "token": f"Bearer {token}",
                "region": "IND",
                "server_url": IND_SERVER_URL,
                "expires_at": time.time() + 25200
            }
    except Exception as e:
        print(f"❌ JWT API exception: {e}")
        return None

# =============================================
# Token Getter (with Cache & Fallback)
# =============================================
async def get_token():
    cached = _token_cache.get("IND")
    if cached and cached.get('expires_at', 0) > time.time():
        return cached

    token_info = await get_jwt_token_from_api()

    if not token_info:
        token_info = await generate_token_backup()

    if token_info:
        _token_cache["IND"] = token_info
        return token_info

    print("❌ Unable to acquire IND bot token. Account may be banned or API unreachable.")
    return None

async def generate_token_backup():
    try:
        account = f"uid={IND_BOT_CREDS['uid']}&password={IND_BOT_CREDS['password']}"

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

        url = f"{IND_LOGIN_URL}/MajorLogin"

        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, data=payload, headers=headers)
            if resp.status_code != 200:
                print(f"❌ Backup MajorLogin failed: {resp.status_code}")
                return None

            if b"Exploiting loopholes" in resp.content or b"Modifiers" in resp.content:
                print(f"🚨 Bot account (UID: {IND_BOT_CREDS['uid']}) is BANNED by Garena!")
                return None

            try:
                login_res = FreeFire_pb2.LoginRes()
                login_res.ParseFromString(resp.content)
                msg_json = json_format.MessageToJson(login_res)
                msg = json.loads(msg_json)
                if not msg.get("token"):
                    print(f"⚠️ MajorLogin returned no token for UID {IND_BOT_CREDS['uid']}")
                    return None
            except Exception as parse_err:
                print(f"⚠️ MajorLogin parse error: {parse_err}")
                return None

            return {
                'token': f"Bearer {msg.get('token','0')}",
                'region': "IND",
                'server_url': msg.get('serverUrl', IND_SERVER_URL),
                'expires_at': time.time() + 25200
            }
    except Exception as e:
        print(f"❌ Backup token error: {e}")
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
# FETCH ACCOUNT INFO FROM GARENA (IND ONLY)
# =============================================
async def GetAccountInformation(uid: int):
    try:
        token_info = await get_token()
        if not token_info:
            return {"success": False, "error_type": "NO_TOKEN"}

        token = token_info['token']
        server_url = token_info['server_url']

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
            'ReleaseVersion': RELEASEVERSION
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(server_url + '/GetPlayerPersonalShow', data=data_enc, headers=headers)

            if resp.status_code != 200:
                print(f"⚠️ GetPlayerPersonalShow returned {resp.status_code} for UID {uid}")
                if resp.status_code in (401, 429):
                    _token_cache.pop("IND", None)
                err_type = "RATE_LIMITED" if resp.status_code == 429 else "NOT_FOUND"
                return {"success": False, "error_type": err_type, "status_code": resp.status_code}

            account_info = AccountPersonalShow_pb2.AccountPersonalShowInfo()
            account_info.ParseFromString(resp.content)
            result = json.loads(json_format.MessageToJson(account_info))

            is_banned = result.get("isBanned", False)
            if isinstance(is_banned, bool):
                result["ban_status"] = "🔴 BANNED" if is_banned else "🟢 UNBANNED"
            else:
                result["ban_status"] = "❓ UNKNOWN"

            result["region"] = "IND"
            return {"success": True, "data": result}

    except Exception as e:
        print(f"❌ Error in GetAccountInformation: {e}")
        return {"success": False, "error_type": "EXCEPTION", "error": str(e)}

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
        dt = datetime.fromtimestamp(int(ts)) + timedelta(hours=5, minutes=30)
        return dt.strftime("%d %b %Y at %I:%M:%S %p") + " (IST)"
    except:
        return "N/A"

# =============================================
# MAIN API ROUTE (/player-info)
# =============================================
@app.route('/player-info')
def player_info():
    uid = request.args.get('uid')
    region = (request.args.get('region') or '').strip().upper()

    # 1. UID वैलिडेशन
    if not uid:
        return jsonify({"status": "error", "message": "Query parameter 'uid' is required."}), 400

    try:
        uid_int = int(uid)
    except:
        return jsonify({"status": "error", "message": "Invalid UID format. UID must be a number."}), 400

    # 2. Region वैलिडेशन (केवल IND मान्य है)
    if not region:
        return jsonify({"status": "error", "message": "Query parameter 'region' is required (Use region=IND)."}), 400

    if region != "IND":
        return jsonify({
            "status": "error",
            "message": f"Region '{region}' is not supported. This API only supports region 'IND'."
        }), 400

    # 3. सीधे Garena IND सर्वर से डेटा प्राप्त करें
    try:
        res = asyncio.run(GetAccountInformation(uid_int))
    except Exception as e:
        return jsonify({"status": "error", "message": f"Internal server error: {str(e)}"}), 500

    if not res.get("success"):
        err_type = res.get("error_type")
        if err_type == "NO_TOKEN":
            return jsonify({
                "status": "error",
                "error": "Bot account for IND is unavailable or banned.",
                "message": "Failed to authenticate bot for region IND. Please check credentials or token API."
            }), 503
        elif err_type == "RATE_LIMITED":
            return jsonify({
                "status": "error",
                "error": "Rate limited by Garena",
                "message": "IND Bot account is currently rate limited by Garena. Please wait a moment."
            }), 429
        else:
            return jsonify({
                "status": "error",
                "message": "Player not found in IND region or server error occurred."
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
        "region_queried": "IND",
        "server_used": "IND",
        "BanStatus": account_data.get("ban_status", "❓ UNKNOWN"),
        "BasicInformation": {
            "PrimeLevel": prime_level,
            "Name": basic.get("nickname", "N/A"),
            "UID": uid,
            "Level": basic.get("level", "N/A"),
            "Exp": basic.get("exp", "N/A"),
            "Region": basic.get("region", "IND"),
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
            "Region": captain.get("region", "IND"),
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
        "endpoint": "/player-info?region=IND&uid=UID",
        "example": "/player-info?region=IND&uid=9230844760",
        "supported_regions": ["IND"]
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
