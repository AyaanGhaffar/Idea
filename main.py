"""
GR GLORY BOT — Multi-Account Glory Points Bot
==============================================
Generates 4 fresh Garena guest accounts on every run, saves them to
bot.txt (uid:password per line, PK region), and uses those accounts.
Bots are labelled GR GLORY 1 through GR GLORY 4.

Flow
----
0.  Generate 4 fresh Garena guest accounts (GR GLORY 1–4), save to bot.txt.
1.  Login all 4 accounts via Garena OAuth + MajorLogin (concurrent).
2.  Connect each account to the Online TCP server and Chat TCP server.
3.  [Optional] All 4 accounts send a guild join-request to GUILD_ID.
4.  Account[0] (leader) opens a squad.
5.  Accounts[1-3] send join-requests to the leader's squad.
6.  After the squad is full, the leader starts the match.
7.  All 4 accounts hold the connection for START_SPAM_DURATION seconds
    so the server records the match entry and queues glory-point credit.
8.  All 4 accounts send leave/disconnect packets to back out.
9.  Connections are cleanly closed.
10. Glory monitor prints per-bot glory point delta for each session.

Note
----
* "Back out but still get glory points" works because Free Fire credits
  glory points when a match is *entered* (loading screen), not when it
  is completed.  Disconnecting during loading registers the match.
* If squad-join fails (e.g. team-code not yet read from TCP stream),
  each bot falls back to independent matchmaking — glory points still
  award per account.
* Set GUILD_ID to the target guild's numeric ID to have all 4 bots
  request to join that guild each session.  Set it to None to skip.
"""

import asyncio
import os
import random
import traceback
import binascii
import json
import socket
import time
import hmac
import hashlib
import string
import base64
import codecs
from typing import Optional

import requests
import urllib3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from bot_files import (
    DEcwHisPErMsG_pb2, MajoRLoGinrEs_pb2, PorTs_pb2,
    MajoRLoGinrEq_pb2, sQ_pb2, Team_msg_pb2,
    RemoveFriend_Req_pb2, GetFriend_Res_pb2,
    spam_request_pb2, devxt_count_pb2, dev_generator_pb2,
    kyro_title_pb2, room_join_pb2,
)

from xC4 import *
from xHeaders import *

try:
    import dns.resolver as _dns_resolver
    _dns_res = _dns_resolver.Resolver()
    _dns_res.nameservers = ['8.8.8.8', '1.1.1.1']
    _orig_getaddrinfo = socket.getaddrinfo

    def _patched_getaddrinfo(host, port, family=0, typ=0, proto=0, flags=0):
        if isinstance(host, str) and 'freefiremobile.com' in host:
            try:
                answers = _dns_res.resolve(host, 'A')
                host = str(answers[0])
            except Exception:
                pass
        return _orig_getaddrinfo(host, port, family, typ, proto, flags)

    socket.getaddrinfo = _patched_getaddrinfo
except ImportError:
    pass


# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════
REGION              = 'PK'
BOT_FILE            = 'bot.txt'
MAX_ACCOUNTS        = 4

GUILD_ID            = 3083083696

SQUAD_JOIN_WAIT     = 3
POST_SQUAD_WAIT     = 3
START_SPAM_DURATION = 18
BACKOUT_DELAY       = 0.5

GLORY_API_BASE      = 'https://clientbp.common.ggbluefox.com'


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
def load_accounts(path: str) -> list[dict]:
    """Read uid:password lines from bot.txt."""
    accounts: list[dict] = []
    if not os.path.exists(path):
        print(f"❌  '{path}' not found.  "
              f"Create it with one uid:password per line.")
        return accounts
    with open(path, 'r', encoding='utf-8') as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if ':' not in line:
                print(f"⚠️   Skipping invalid line (need uid:password): {line!r}")
                continue
            uid, pw = line.split(':', 1)
            accounts.append({'uid': uid.strip(), 'password': pw.strip()})
            if len(accounts) >= MAX_ACCOUNTS:
                break
    return accounts


# ── Najmi GST guest-generator constants ─────────────────────────────────────
_NAJMI_HMAC_KEY_HEX = (
    "32656534343831396539623435393838343531343130363762323831363231383"
    "734643064356437616639643866376530306331653534373135623764316533"
)
_NAJMI_KEY = bytes.fromhex(_NAJMI_HMAC_KEY_HEX)

_NAJMI_AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
_NAJMI_AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

_NAJMI_GARENA_BASE64 = "QllfU1BJREVFUklPX0dBTUlORw=="


def _najmi_generate_password(prefix: str = "GRGLORY") -> str:
    """Generate a custom password using Najmi's scheme."""
    garena_decoded = base64.b64decode(_NAJMI_GARENA_BASE64).decode('utf-8')
    chars = string.ascii_uppercase + string.digits
    r1 = ''.join(random.choice(chars) for _ in range(5))
    r2 = ''.join(random.choice(chars) for _ in range(5))
    return f"{prefix}_{r1}_{garena_decoded}_{r2}"


def _najmi_aes_encrypt(hex_data: str) -> bytes:
    """AES-CBC encrypt hex-encoded bytes using Najmi's key/IV."""
    plain = bytes.fromhex(hex_data)
    cipher = AES.new(_NAJMI_AES_KEY, AES.MODE_CBC, _NAJMI_AES_IV)
    return cipher.encrypt(pad(plain, AES.block_size))


def _najmi_encode_open_id(original: str) -> dict:
    """XOR-encode the open_id as Najmi does."""
    keystream = [
        0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31,
        0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30,
    ]
    encoded = ""
    for i, ch in enumerate(original):
        encoded += chr(ord(ch) ^ keystream[i % len(keystream)])
    return {"open_id": original, "field_14": encoded}


def _najmi_to_unicode_escaped(s: str) -> str:
    return ''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in s)


def _najmi_encode_varint(n: int) -> bytes:
    if n < 0:
        return b''
    buf = []
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        buf.append(b)
        if not n:
            break
    return bytes(buf)


def _najmi_proto_varint(field: int, value: int) -> bytes:
    return _najmi_encode_varint((field << 3) | 0) + _najmi_encode_varint(value)


def _najmi_proto_length(field: int, value) -> bytes:
    hdr = _najmi_encode_varint((field << 3) | 2)
    enc = value.encode() if isinstance(value, str) else value
    return hdr + _najmi_encode_varint(len(enc)) + enc


def _najmi_build_proto(fields: dict) -> bytes:
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested = _najmi_build_proto(value)
            packet.extend(_najmi_proto_length(field, nested))
        elif isinstance(value, int):
            packet.extend(_najmi_proto_varint(field, value))
        else:
            packet.extend(_najmi_proto_length(field, value))
    return bytes(packet)


def _najmi_guest_register(password: str) -> Optional[dict]:
    """
    Register a new Garena guest account.
    Returns {'uid': str, 'password': str} or None on failure.
    """
    data_str = f"password={password}&client_type=2&source=2&app_id=100067"
    message   = data_str.encode('utf-8')
    signature = hmac.new(_NAJMI_KEY, message, hashlib.sha256).hexdigest()

    url     = "https://100067.connect.garena.com/oauth/guest/register"
    headers = {
        "User-Agent":      "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
        "Authorization":   "Signature " + signature,
        "Content-Type":    "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip",
        "Connection":      "Keep-Alive",
    }

    try:
        resp = requests.post(url, headers=headers, data=data_str, timeout=30, verify=False)
        print(f"[GuestGen] register → HTTP {resp.status_code}")
        j = resp.json()
        if 'uid' in j:
            return {"uid": str(j['uid']), "password": password}
        print(f"[GuestGen] register response: {j}")
    except Exception as exc:
        print(f"[GuestGen] register error: {exc}")
    return None


def _najmi_token_grant(uid: str, password: str) -> Optional[dict]:
    """
    Grant an OAuth token for an existing guest account.
    Returns {'open_id': str, 'access_token': str} or None.
    """
    url     = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Accept-Encoding": "gzip",
        "Connection":      "Keep-Alive",
        "Content-Type":    "application/x-www-form-urlencoded",
        "Host":            "100067.connect.garena.com",
        "User-Agent":      "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
    }
    body = {
        "uid":           uid,
        "password":      password,
        "response_type": "token",
        "client_type":   "2",
        "client_secret": _NAJMI_KEY.decode('latin-1'),  # bytes → str, preserves exact values
        "client_id":     "100067",
    }
    try:
        resp = requests.post(url, headers=headers, data=body, timeout=30, verify=False)
        print(f"[GuestGen] token grant → HTTP {resp.status_code}")
        j = resp.json()
        if 'open_id' in j:
            return {
                "open_id":      j['open_id'],
                "access_token": j['access_token'],
            }
        print(f"[GuestGen] token grant response: {j}")
    except Exception as exc:
        print(f"[GuestGen] token grant error: {exc}")
    return None


def _najmi_major_register(
    access_token: str, open_id: str, uid: str, password: str,
    account_name: str, region: str = "PK"
) -> bool:
    """
    Register the guest account on the Free Fire game server (MajorRegister).
    Returns True on success.
    """
    encoded = _najmi_encode_open_id(open_id)
    field_14_esc = _najmi_to_unicode_escaped(encoded["field_14"])
    field_14 = codecs.decode(field_14_esc, 'unicode_escape').encode('latin1')

    lang_code = "ur"    # PK region
    payload_fields = {
        1:  account_name,
        2:  access_token,
        3:  open_id,
        5:  102000007,
        6:  4,
        7:  1,
        13: 1,
        14: field_14,
        15: lang_code,
        16: 1,
        17: 1,
    }
    proto_bytes     = _najmi_build_proto(payload_fields)
    encrypted_bytes = _najmi_aes_encrypt(proto_bytes.hex())

    url = "https://loginbp.ggblueshark.com/MajorRegister"
    headers = {
        "Accept-Encoding": "gzip",
        "Authorization":   "Bearer",
        "Connection":      "Keep-Alive",
        "Content-Type":    "application/x-www-form-urlencoded",
        "Expect":          "100-continue",
        "Host":            "loginbp.ggblueshark.com",
        "ReleaseVersion":  "OB52",
        "User-Agent":      "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
        "X-GA":            "v1 1",
        "X-Unity-Version": "2018.4.",
    }
    try:
        resp = requests.post(
            url, headers=headers, data=encrypted_bytes, verify=False, timeout=30
        )
        return resp.status_code == 200
    except Exception as exc:
        print(f"[GuestGen] MajorRegister error: {exc}")
        return False


_EXPONENT_DIGITS = {'0':'⁰','1':'¹','2':'²','3':'³','4':'⁴',
                    '5':'⁵','6':'⁶','7':'⁷','8':'⁸','9':'⁹'}


def _najmi_random_ingame_name(base: str) -> str:
    """
    Build a unique in-game name using Najmi's exponent-suffix scheme.
    Takes first 7 chars of base + 5 random superscript digits.
    Guarantees a fresh unique name on every call.
    """
    number = random.randint(10000, 99999)
    suffix = ''.join(_EXPONENT_DIGITS[d] for d in str(number))
    return f"{base[:7]}{suffix}"


def _najmi_create_one_guest(label: str, region: str = "PK") -> Optional[dict]:
    """
    Full Najmi flow: register guest → grant token → MajorRegister.

    Step 1 (Garena register) is the ONLY hard requirement — if it
    returns a uid we already have a valid credential pair and save it.
    Steps 2 & 3 are best-effort: failures are logged but do NOT cause
    the account to be discarded.
    Returns {'uid': str, 'password': str} or None only if Step 1 fails.
    """
    password = _najmi_generate_password("GRGLORY")

    # ── Step 1: Garena guest register (REQUIRED) ──────────────────────────
    acc = _najmi_guest_register(password)
    if not acc:
        return None                # only hard failure → caller retries
    uid = acc['uid']
    print(f"[GuestGen] {label} — Garena UID {uid} created ✅")

    time.sleep(0.030)

    # ── Step 2: OAuth token grant ─────────────────────────────────────────
    tok = _najmi_token_grant(uid, password)
    if not tok:
        print(f"[GuestGen] {label} — token grant failed, will retry with new account")
        return None   # caller retries — unregistered accounts are useless

    time.sleep(0.030)

    # ── Step 3: MajorRegister — retry with new name on duplicate ─────────
    NAME_RETRIES = 5
    registered = False
    for name_attempt in range(1, NAME_RETRIES + 1):
        ingame_name = _najmi_random_ingame_name(label)
        ok = _najmi_major_register(
            tok['access_token'], tok['open_id'],
            uid, password, ingame_name, region
        )
        if ok:
            print(f"[GuestGen] {label} — registered in-game as '{ingame_name}' ✅")
            registered = True
            break
        print(f"[GuestGen] {label} — MajorRegister attempt {name_attempt}/{NAME_RETRIES} "
              f"failed (name='{ingame_name}'), trying new name …")
        time.sleep(0.030)

    if not registered:
        print(f"[GuestGen] {label} — MajorRegister exhausted, will retry with new account")
        return None   # account exists on Garena but not in-game — unusable

    return {"uid": uid, "password": password}


async def _fetch_najmi_accounts(count: int) -> list[dict]:
    """
    Generate `count` guest accounts using Najmi's real Garena API.
    Keeps retrying each slot indefinitely until it succeeds — no hard cap.
    Returns a list of {'uid': ..., 'password': ...} dicts (always `count` long).
    """
    loop    = asyncio.get_running_loop()
    results = []

    for i in range(count):
        label   = f"GR GLORY {i + 1}"
        attempt = 0

        while True:
            attempt += 1
            print(f"[GuestGen] {label} — attempt {attempt} …")
            acc = await loop.run_in_executor(
                None, lambda lbl=label: _najmi_create_one_guest(lbl, REGION)
            )
            if acc:
                results.append(acc)
                print(f"[GuestGen] ✅  {label} created (UID {acc['uid']})")
                break

            print(f"[GuestGen] {label} failed — retrying in 2s …")
            await asyncio.sleep(2)

    return results


async def generate_guest_accounts(path: str, count: int) -> list[dict]:
    """Generate `count` fresh Garena guest accounts, save them to `path`, and return them."""
    # Always wipe bot.txt first so stale accounts never interfere
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write("")
    print(f"  🗑️   Cleared {path} — starting fresh generation …")

    sep = "─" * 60
    print(f"\n{sep}")
    print(f"  Generating {count} guest account(s) — GR GLORY 1 … GR GLORY {count}")
    print(f"  (using Najmi GST Generator — real Garena API) …")
    print(f"{sep}\n")

    accounts = await _fetch_najmi_accounts(count)

    if len(accounts) < count:
        print(f"\n❌  Only got {len(accounts)}/{count} accounts from Garena.")
        print("    Check your internet connection and retry.\n")
        return []

    accounts = accounts[:count]
    for i, acc in enumerate(accounts):
        print(f"  [GR GLORY {i + 1}] UID {acc['uid']}  ✅")

    # Write all accounts to bot.txt
    lines = [
        "# bot.txt — Auto-generated Garena guest accounts",
        f"# Format: uid:password  (GR GLORY 1 … GR GLORY {count})",
        "# DO NOT edit manually — regenerated each run",
        "",
    ]
    for i, acc in enumerate(accounts):
        lines.append(f"# GR GLORY {i + 1}")
        lines.append(f"{acc['uid']}:{acc['password']}")

    with open(path, 'w', encoding='utf-8') as fh:
        fh.write("\n".join(lines) + "\n")

    print(f"\n  ✅  {count} guest account(s) saved to {path}\n")
    return accounts


def dec_to_hex(n: int) -> str:
    h = hex(n)[2:].upper()
    return h if len(h) % 2 == 0 else '0' + h


def varint_encode(value: int) -> str:
    buf = []
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            b |= 0x80
        buf.append(b)
        if not value:
            break
    return ''.join(f'{b:02x}' for b in buf)


# ═══════════════════════════════════════════════════════════════════════════════
#  GLORY MONITOR
# ═══════════════════════════════════════════════════════════════════════════════
class GloryMonitor:
    """
    Tracks glory points for each bot before and after a session.
    Uses the same AES + protobuf pattern as the rest of the codebase
    to query the GetPlayerPersonalShow endpoint.

    Glory points are stored in field path:
      response["1"]["data"]["8"]["data"]   (season glory / ranked points)
    Adjust the path below if the server returns them differently.
    """

    def __init__(self):
        self._snapshots: dict[str, dict] = {}

    # ── Internal: fetch raw player-info blob ──────────────────────────────────
    async def _fetch_player_info(self, uid: str, token: str) -> Optional[dict]:
        """
        POST /GetPlayerPersonalShow with AES-encrypted protobuf body.
        Returns the decoded JSON dict or None on failure.
        """
        try:
            uid_hex = await EnC_Uid(int(uid), Tp='Uid')
            raw_hex = f"08{uid_hex}1007"
            data    = bytes.fromhex(await EnC_AEs(raw_hex))

            headers = {
                'X-Unity-Version':  '2018.4.11f1',
                'ReleaseVersion':   'OB52',
                'Content-Type':     'application/x-www-form-urlencoded',
                'X-GA':             'v1 1',
                'Authorization':    f'Bearer {token}',
                'User-Agent':       ('Dalvik/2.1.0 '
                                     '(Linux; U; Android 9; SM-A515F Build/PI)'),
                'Connection':       'Keep-Alive',
                'Accept-Encoding':  'gzip',
            }

            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(
                None,
                lambda: requests.post(
                    f'{GLORY_API_BASE}/GetPlayerPersonalShow',
                    headers=headers, data=data, verify=False, timeout=10
                )
            )

            if resp.status_code not in (200, 201):
                return None

            packet_hex = binascii.hexlify(resp.content).decode('utf-8')
            decoded    = await DeCode_PackEt(packet_hex)
            if decoded is None:
                return None
            return json.loads(decoded)

        except Exception as exc:
            print(f"[GloryMonitor] ⚠️  fetch error for UID {uid}: {exc}")
            return None

    # ── Extract glory points from decoded response ────────────────────────────
    @staticmethod
    def _extract_glory(data: dict) -> Optional[int]:
        """
        Try known field paths for glory / ranked / season points.
        Returns an integer if found, else None.
        """
        if data is None:
            return None
        try:
            # Primary path: ranked season points (field 8 inside field 1)
            return int(data["1"]["data"]["8"]["data"])
        except (KeyError, TypeError, ValueError):
            pass
        try:
            # Alternate: total glory stored separately
            return int(data["8"]["data"])
        except (KeyError, TypeError, ValueError):
            pass
        return None

    # ── Public API ────────────────────────────────────────────────────────────
    async def snapshot(self, bot_index: int, uid: str, token: str, label: str = "before"):
        """Take a glory-points snapshot for one bot."""
        info    = await self._fetch_player_info(uid, token)
        points  = self._extract_glory(info)
        key     = f"bot{bot_index}"
        if key not in self._snapshots:
            self._snapshots[key] = {}
        self._snapshots[key][label] = points
        status  = str(points) if points is not None else "N/A"
        bot_label = f"GR GLORY {bot_index + 1}"
        print(f"[GloryMonitor] {bot_label} (UID {uid})  "
              f"{label.upper()} glory = {status}")

    def report(self, bots: list) -> str:
        """
        Print and return a summary table of glory gained per bot.
        Call after all 'after' snapshots have been taken.
        """
        sep  = "─" * 58
        lines = [
            "",
            sep,
            "  GLORY MONITOR — SESSION RESULTS",
            sep,
            f"  {'Bot':<12} {'UID':<14} {'Before':>8} {'After':>8} {'Gained':>8}",
            sep,
        ]

        total_gained = 0
        for bot in bots:
            key    = f"bot{bot.index}"
            snap   = self._snapshots.get(key, {})
            before = snap.get('before')
            after  = snap.get('after')
            gained = (after - before) if (before is not None and after is not None) else None

            b_str  = str(before) if before is not None else "N/A"
            a_str  = str(after)  if after  is not None else "N/A"
            g_str  = (f"+{gained}" if gained and gained > 0 else str(gained)) \
                     if gained is not None else "N/A"

            if gained is not None:
                total_gained += gained

            lines.append(
                f"  {bot.bot_label:<12} {bot.account_uid or bot.uid:<14} "
                f"{b_str:>8} {a_str:>8} {g_str:>8}"
            )

        lines += [
            sep,
            f"  Total glory gained this session: {total_gained}",
            sep,
            "",
        ]
        result = "\n".join(lines)
        print(result)
        return result


# ═══════════════════════════════════════════════════════════════════════════════
#  BOT ACCOUNT  (one instance per loaded account)
# ═══════════════════════════════════════════════════════════════════════════════
class BotAccount:
    """One Free Fire account: login → TCP connect → send squad/match packets."""

    HEARTBEAT_INTERVAL = 10  # seconds between keep-alive pings

    def __init__(self, uid: str, password: str, index: int):
        self.uid        = uid
        self.password   = password
        self.index      = index
        self.bot_label  = f"GR GLORY {index + 1}"   # e.g. "GR GLORY 1"

        self.open_id      : str   = None
        self.access_token : str   = None
        self.token        : str   = None
        self.url          : str   = None
        self.key          : bytes = None
        self.iv           : bytes = None
        self.region       : str   = REGION
        self.account_uid  : str   = None
        self.account_name : str   = None

        self.online_reader  = None
        self.online_writer  = None
        self.whisper_reader = None
        self.whisper_writer = None

        self._online_ip   : str = None
        self._online_port : int = None
        self._chat_ip     : str = None
        self._chat_port   : int = None

        self._heartbeat_task  : asyncio.Task = None
        self._reader_task     : asyncio.Task = None
        self._connection_dead : bool         = False

    # ────────────────────────────────────────────────────────────────────────
    # 1. Login
    # ────────────────────────────────────────────────────────────────────────
    async def login(self) -> bool:
        print(f"[{self.bot_label}] 🔐  Logging in UID {self.uid} …")
        try:
            self.open_id, self.access_token = await GeNeRaTeAccEss(
                self.uid, self.password
            )
            if not self.open_id or not self.access_token:
                print(f"[{self.bot_label}] ❌  Garena token failed for UID {self.uid}")
                return False

            payload           = await EncRypTMajoRLoGin(self.open_id, self.access_token)
            login_response    = await MajorLogin(payload)
            if not login_response:
                print(f"[{self.bot_label}] ❌  MajorLogin failed "
                      f"(account banned or not registered)")
                return False

            auth              = await DecRypTMajoRLoGin(login_response)
            self.token        = auth.token
            self.url          = auth.url
            self.key          = auth.key
            self.iv           = auth.iv
            self.account_uid  = auth.account_uid
            self.region       = getattr(auth, 'region', REGION)

            if not self.token:
                print(f"[{self.bot_label}] ❌  No JWT in login response")
                return False

            login_data  = await GetLoginData(self.url, payload, self.token)
            if not login_data:
                print(f"[{self.bot_label}] ❌  GetLoginData failed")
                return False

            info = await DecRypTLoGinDaTa(login_data)
            self.account_name = info.AccountName

            self._online_ip, op = info.Online_IP_Port.split(':')
            self._chat_ip,   cp = info.AccountIP_Port.split(':')
            self._online_port   = int(op)
            self._chat_port     = int(cp)

            print(f"[{self.bot_label}] ✅  {self.account_name} "
                  f"(UID {self.account_uid})  region={self.region}")
            return True

        except Exception as exc:
            print(f"[{self.bot_label}] ❌  Login error: {exc}")
            traceback.print_exc()
            return False

    # ────────────────────────────────────────────────────────────────────────
    # 2. TCP Connections
    # ────────────────────────────────────────────────────────────────────────
    async def connect(self) -> bool:
        ok_online = await self._connect_online()
        ok_chat   = await self._connect_chat()
        return ok_online and ok_chat

    async def _connect_online(self) -> bool:
        try:
            # Reset dead-connection flag so the new connection starts clean
            self._connection_dead = False

            auth_pkt = await MaKe_OnLine_Packet(
                self.token, self.key, self.iv,
                self.account_uid, self.region
            )
            reader, writer = await asyncio.open_connection(
                self._online_ip, self._online_port
            )
            writer.write(auth_pkt)
            await writer.drain()
            self.online_reader = reader
            self.online_writer = writer

            # Wait briefly for the server to acknowledge the auth packet
            await asyncio.sleep(1)

            # Start background heartbeat to keep the bot online
            self._stop_heartbeat()
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            self._reader_task    = asyncio.create_task(self._read_online_loop())

            print(f"[{self.bot_label}] 🟢  Online connected + heartbeat started "
                  f"({self._online_ip}:{self._online_port})")
            return True
        except Exception as exc:
            print(f"[{self.bot_label}] ❌  Online TCP: {exc}")
            return False

    async def _connect_chat(self) -> bool:
        try:
            auth_pkt = await MaKe_WispeR_Packet(
                self.token, self.key, self.iv,
                self.account_uid, self.region
            )
            reader, writer = await asyncio.open_connection(
                self._chat_ip, self._chat_port
            )
            writer.write(auth_pkt)
            await writer.drain()
            self.whisper_reader = reader
            self.whisper_writer = writer
            print(f"[{self.bot_label}] 🟢  Chat connected "
                  f"({self._chat_ip}:{self._chat_port})")
            return True
        except Exception as exc:
            print(f"[{self.bot_label}] ❌  Chat TCP: {exc}")
            return False

    # ────────────────────────────────────────────────────────────────────────
    # 2b. Heartbeat & reader to stay ONLINE
    # ────────────────────────────────────────────────────────────────────────
    async def _build_keepalive_packet(self) -> bytes:
        """
        Build a proper FF keep-alive packet.

        The FF online-presence server expects a periodic re-auth / ping that
        is structurally identical to the initial auth packet sent on connect.
        Re-sending MaKe_OnLine_Packet keeps the server's presence timer reset
        so the player appears 'online now' rather than 'online X min ago'.

        Falls back to a minimal encrypted empty-body packet if the auth
        builder fails for any reason.
        """
        try:
            pkt = await MaKe_OnLine_Packet(
                self.token, self.key, self.iv,
                self.account_uid, self.region
            )
            return pkt
        except Exception:
            pass
        # Fallback: AES-encrypt an empty protobuf body (field 1 = uid only)
        try:
            uid_hex = await EnC_Uid(int(self.account_uid), Tp='Uid')
            raw_hex = f"08{uid_hex}"
            enc_hex = await EnC_AEs(raw_hex)
            return bytes.fromhex(enc_hex)
        except Exception:
            # Last resort — raw 5-byte null frame (keeps TCP alive at minimum)
            return b'\x00\x05\x00\x00\x00'

    async def _heartbeat_loop(self):
        """
        Send periodic keep-alive packets so the server keeps the bot ONLINE.

        Interval:  10 s  (HEARTBEAT_INTERVAL)
        Every tick: re-send the full online-auth packet so the presence server
                    resets its 'last seen' timer → bot stays 'online now'.
        """
        try:
            while True:
                await asyncio.sleep(self.HEARTBEAT_INTERVAL)
                if self.online_writer is None or self.online_writer.is_closing():
                    print(f"[{self.bot_label}] ⚠️  Heartbeat: writer gone — stopping")
                    break
                if self._connection_dead:
                    break
                try:
                    heartbeat_pkt = await self._build_keepalive_packet()
                    self.online_writer.write(heartbeat_pkt)
                    await self.online_writer.drain()
                except (ConnectionResetError, BrokenPipeError, OSError) as hb_exc:
                    print(f"[{self.bot_label}] ⚠️  Heartbeat failed — connection lost"
                          f" ({hb_exc})")
                    self._connection_dead = True
                    break
        except asyncio.CancelledError:
            pass

    async def _read_online_loop(self):
        """Read and discard server packets to keep the TCP connection healthy."""
        try:
            while True:
                if self.online_reader is None:
                    break
                try:
                    data = await self.online_reader.read(4096)
                except (ConnectionResetError, BrokenPipeError, OSError) as rd_exc:
                    print(f"[{self.bot_label}] ⚠️  Online read error — connection lost"
                          f" ({rd_exc})")
                    self._connection_dead = True
                    break
                if not data:
                    # Server sent EOF — connection is gone
                    print(f"[{self.bot_label}] ⚠️  Server closed online connection (EOF)")
                    self._connection_dead = True
                    break
                # Server responses are received but not processed here;
                # keeping the read loop prevents TCP buffer from filling up.
        except asyncio.CancelledError:
            pass

    def _stop_heartbeat(self):
        """Cancel background heartbeat and reader tasks if running."""
        for task in (self._heartbeat_task, self._reader_task):
            if task and not task.done():
                task.cancel()
        self._heartbeat_task = None
        self._reader_task    = None

    # ────────────────────────────────────────────────────────────────────────
    # 3. Packet senders
    # ────────────────────────────────────────────────────────────────────────
    async def send_online(self, pkt: bytes):
        try:
            if self.online_writer and not self.online_writer.is_closing():
                self.online_writer.write(pkt)
                await self.online_writer.drain()
        except Exception as exc:
            print(f"[{self.bot_label}] ⚠️   Online send error: {exc}")

    async def send_chat(self, pkt: bytes):
        try:
            if self.whisper_writer and not self.whisper_writer.is_closing():
                self.whisper_writer.write(pkt)
                await self.whisper_writer.drain()
        except Exception as exc:
            print(f"[{self.bot_label}] ⚠️   Chat send error: {exc}")

    # ────────────────────────────────────────────────────────────────────────
    # 4. Game actions
    # ────────────────────────────────────────────────────────────────────────
    async def create_squad(self):
        try:
            pkt = await OpEnSq(self.key, self.iv, self.region)
            await self.send_online(pkt)
            print(f"[{self.bot_label}] 🏠  Squad opened")
        except Exception as exc:
            print(f"[{self.bot_label}] ⚠️   create_squad: {exc}")

    async def join_leader_squad(self, leader_uid: str):
        try:
            pkt = await ReQuEsTJoInTeAm(
                leader_uid, self.key, self.iv, self.region
            )
            await self.send_online(pkt)
            print(f"[{self.bot_label}] 📨  Join-request → leader {leader_uid}")
        except NameError:
            try:
                pkt = await ghost_pakcet(
                    self.account_uid, leader_uid,
                    self.key, self.iv
                )
                await self.send_online(pkt)
                print(f"[{self.bot_label}] 📨  Ghost-join → leader {leader_uid}")
            except Exception as exc2:
                print(f"[{self.bot_label}] ⚠️   join fallback failed: {exc2}")
        except Exception as exc:
            print(f"[{self.bot_label}] ⚠️   join_leader_squad: {exc}")

    async def send_ready(self):
        """Send ready/confirm packet so the server knows this bot is ready to play."""
        try:
            # Build a ready-confirmation packet using the same encryption
            uid_hex = await EnC_Uid(int(self.account_uid), Tp='Uid')
            # Ready packet: field 1 = uid, field 2 = ready state (1)
            raw_hex = f"08{uid_hex}1001"
            encrypted = await EnC_AEs(raw_hex)
            pkt = bytes.fromhex(encrypted)
            await self.send_online(pkt)
            print(f"[{self.bot_label}] ✅  Ready packet sent")
        except Exception as exc:
            print(f"[{self.bot_label}] ⚠️   send_ready: {exc}")

    async def confirm_match(self):
        """Send match confirmation — all bots must confirm, not just the leader."""
        try:
            pkt = await FS(self.key, self.iv, self.region)
            await self.send_online(pkt)
            print(f"[{self.bot_label}] 🎮  Match confirm packet sent")
        except Exception as exc:
            print(f"[{self.bot_label}] ⚠️   confirm_match: {exc}")

    @staticmethod
    def _build_varint(value: int) -> bytes:
        """Encode a non-negative integer as a protobuf varint."""
        buf = []
        while True:
            b = value & 0x7F
            value >>= 7
            if value:
                b |= 0x80
            buf.append(b)
            if not value:
                break
        return bytes(buf)

    @staticmethod
    def _build_proto_field(field_number: int, value: int) -> bytes:
        """Encode a single varint protobuf field (wire type 0)."""
        tag = (field_number << 3) | 0   # wire type 0 = varint
        result = bytearray()
        # encode tag as varint
        t = tag
        while True:
            b = t & 0x7F
            t >>= 7
            if t:
                b |= 0x80
            result.append(b)
            if not t:
                break
        # encode value as varint
        v = value
        while True:
            b = v & 0x7F
            v >>= 7
            if v:
                b |= 0x80
            result.append(b)
            if not v:
                break
        return bytes(result)

    @staticmethod
    def _decode_error_response(raw: bytes) -> str:
        """
        Try every known decoding strategy on the server response body and
        return a human-readable error string.

        Strategies (in order):
          1. DeCode_PackEt (game AES decrypt → protobuf JSON)
          2. Plain UTF-8 / latin-1 text
          3. Hex dump of first 64 bytes
        """
        if not raw:
            return "<empty body>"

        # Strategy 1 – try game protobuf decode (runs in a fresh event loop
        # slice so we can call it synchronously from a sync context too)
        try:
            import asyncio as _asyncio
            loop = _asyncio.get_event_loop()
            hex_str = binascii.hexlify(raw).decode()
            decoded = loop.run_until_complete(DeCode_PackEt(hex_str))
            if decoded:
                return f"[proto] {decoded[:300]}"
        except Exception:
            pass

        # Strategy 2 – plain text
        for enc in ('utf-8', 'latin-1'):
            try:
                text = raw.decode(enc).strip()
                if text:
                    return f"[text/{enc}] {text[:300]}"
            except Exception:
                pass

        # Strategy 3 – hex dump
        return f"[hex] {binascii.hexlify(raw[:64]).decode()}"

    async def request_guild_join(self, guild_id: int) -> bool:
        """Send guild join request via HTTP RequestJoinClan endpoint."""
        try:
            # Use EnC_Uid for BOTH fields — the FF server encodes all entity
            # IDs (player UIDs, clan IDs, room IDs …) identically via EnC_Uid.
            # Using a plain varint for field 2 is what caused "clan not found".
            uid_hex   = await EnC_Uid(int(self.account_uid), Tp='Uid')
            clan_hex  = await EnC_Uid(guild_id, Tp='Uid')

            # field 1 = player UID, field 2 = clan/guild ID
            raw_hex   = f"08{uid_hex}10{clan_hex}"

            # AES-encrypt exactly like every other FF HTTP endpoint
            encrypted_hex = await EnC_AEs(raw_hex)
            body          = bytes.fromhex(encrypted_hex)

            headers = {
                'X-Unity-Version':  '2018.4.11f1',
                'ReleaseVersion':   'OB52',
                'Content-Type':     'application/x-www-form-urlencoded',
                'X-GA':             'v1 1',
                'Authorization':    f'Bearer {self.token}',
                'User-Agent':       ('Dalvik/2.1.0 '
                                     '(Linux; U; Android 9; SM-A515F Build/PI)'),
                'Connection':       'Keep-Alive',
                'Accept-Encoding':  'gzip',
            }

            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(
                None,
                lambda: requests.post(
                    f'{GLORY_API_BASE}/RequestJoinClan',
                    headers=headers, data=body, verify=False, timeout=10
                )
            )

            if resp.status_code in (200, 201):
                print(f"[{self.bot_label}] 🏛️  Guild join-request sent "
                      f"→ guild {guild_id}  (HTTP {resp.status_code})")
                return True
            else:
                # Decode the error body with every available strategy
                error_detail = await loop.run_in_executor(
                    None, lambda: self._decode_error_response(resp.content)
                )
                print(f"[{self.bot_label}] ⚠️   Guild join FAILED "
                      f"HTTP {resp.status_code} — {error_detail}")
                return False

        except Exception as exc:
            print(f"[{self.bot_label}] ⚠️   request_guild_join: {exc}")
            traceback.print_exc()
            return False

    async def start_match(self):
        try:
            pkt = await FS(self.key, self.iv, self.region)
            await self.send_online(pkt)
            print(f"[{self.bot_label}] 🎮  Start-match packet sent")
        except Exception as exc:
            print(f"[{self.bot_label}] ⚠️   start_match: {exc}")

    async def leave(self):
        try:
            pkt = await ExiT(int(self.account_uid), self.key, self.iv)
            await self.send_online(pkt)
            print(f"[{self.bot_label}] 🚪  Left match/squad")
        except Exception as exc:
            print(f"[{self.bot_label}] ⚠️   leave: {exc}")

    # ────────────────────────────────────────────────────────────────────────
    # 5. Clean-up
    # ────────────────────────────────────────────────────────────────────────
    async def disconnect(self):
        # Stop heartbeat & reader tasks first
        self._stop_heartbeat()
        for w in (self.online_writer, self.whisper_writer):
            if w and not w.is_closing():
                try:
                    w.close()
                    await w.wait_closed()
                except Exception:
                    pass
        self.online_reader    = None
        self.online_writer    = None
        self.whisper_reader   = None
        self.whisper_writer   = None
        self._connection_dead = False   # reset so next session starts clean
        print(f"[{self.bot_label}] 🔌  Disconnected")


# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — STARTUP  (login → online → guild request)
# ═══════════════════════════════════════════════════════════════════════════════
async def startup_phase(bots: list, glory_monitor: GloryMonitor) -> bool:
    """
    Runs automatically when the script starts.
    1. Login all bots
    2. Connect to TCP (go online in-game)
    3. Send guild join-requests
    Returns True if all bots are ready, False on fatal error.
    """
    separator = "═" * 60
    print(separator)
    print("    GR GLORY BOT  ·  STARTUP PHASE  ·  PK")
    print(separator)

    # ── 1. Login all 4 (concurrent) ───────────────────────────────────────────
    print("\n[*] Logging in all 4 bots …")
    results = await asyncio.gather(*[b.login() for b in bots])
    if not all(results):
        failed = [b.uid for b, ok in zip(bots, results) if not ok]
        print(f"\n❌  Login failed for: {failed}\n    Aborting.")
        return False
    print("[*] All 4 bots authenticated ✅\n")

    # ── 2. Connect all to TCP — bots are now ONLINE in-game ───────────────────
    print("[*] Opening TCP connections (bots going online in-game) …")
    conn_results = await asyncio.gather(*[b.connect() for b in bots])
    if not all(conn_results):
        failed = [b.uid for b, ok in zip(bots, conn_results) if not ok]
        print(f"\n❌  TCP failed for: {failed}")
        for b in bots:
            await b.disconnect()
        return False
    print("[*] All 4 bots are now ONLINE in-game ✅\n")

    await asyncio.sleep(2)

    # ── 3. Send guild join-requests ───────────────────────────────────────────
    if GUILD_ID is not None:
        print(f"[*] Sending guild join-requests → guild {GUILD_ID} …")
        guild_results = await asyncio.gather(
            *[b.request_guild_join(GUILD_ID) for b in bots],
            return_exceptions=True
        )
        ok   = sum(1 for r in guild_results if r is True)
        fail = MAX_ACCOUNTS - ok
        print(f"[*] Guild requests sent — {ok} OK, {fail} skipped/failed\n")
        print("  ℹ️   Accept the guild requests in-game, then press [S] to")
        print("       start glory farming.\n")
    else:
        print("[*] GUILD_ID not set — skipping guild join-requests\n")
        print("  ℹ️   Press [S] to start glory farming.\n")

    return True


# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — GLORY SESSION  (squad → match → back out)
# ═══════════════════════════════════════════════════════════════════════════════
async def glory_session(bots: list, glory_monitor: GloryMonitor):
    """
    Runs each time the user presses S.
    Reconnects any dropped TCP connections, farms one round of glory points.
    """
    separator = "═" * 60

    # ── Reconnect any bots whose TCP dropped between sessions ─────────────────
    print("[*] Checking / restoring TCP connections …")
    for b in bots:
        needs_reconnect = (
            b.online_writer is None or b.online_writer.is_closing() or
            b.whisper_writer is None or b.whisper_writer.is_closing() or
            b._connection_dead  # heartbeat/reader detected a silent drop
        )
        if needs_reconnect:
            reason = "connection_dead flag" if b._connection_dead else "writer closed"
            print(f"  [{b.bot_label}]  TCP lost ({reason}) — reconnecting …")
            ok = await b.connect()
            if not ok:
                print(f"  [{b.bot_label}]  ❌  Reconnect failed — skipping this bot.")
    print("[*] Connection check done ✅\n")

    # ── Take BEFORE glory snapshots ───────────────────────────────────────────
    print("[*] Glory Monitor — taking BEFORE snapshots …")
    await asyncio.gather(*[
        glory_monitor.snapshot(b.index, b.account_uid or b.uid, b.token, label='before')
        for b in bots
    ])
    print()

    # ── Form squad ────────────────────────────────────────────────────────────
    leader  = bots[0]
    members = bots[1:]

    print(f"[*] {leader.bot_label} ({leader.account_name}) creating squad …")
    await leader.create_squad()
    await asyncio.sleep(3)

    print(f"[*] Remaining bots joining {leader.bot_label}'s squad …")
    for bot in members:
        await bot.join_leader_squad(str(leader.account_uid))
        await asyncio.sleep(SQUAD_JOIN_WAIT)

    # Wait for all join requests to be processed by server
    await asyncio.sleep(3)

    # ── All members send READY confirmation ───────────────────────────────────
    print(f"[*] All bots sending ready confirmation …")
    await asyncio.gather(*[b.send_ready() for b in bots])
    await asyncio.sleep(2)

    print(f"[*] Squad formed — 4/4 players ready ✅\n")
    await asyncio.sleep(POST_SQUAD_WAIT)

    # ── Leader starts the match ───────────────────────────────────────────────
    print(f"[*] Starting match (leader: {leader.account_name}) …")
    await leader.start_match()
    await asyncio.sleep(2)

    # ── All bots confirm match entry ──────────────────────────────────────────
    print(f"[*] All bots confirming match entry …")
    await asyncio.gather(*[b.confirm_match() for b in members])
    await asyncio.sleep(2)

    # ── Hold connection during loading (glory point window) ───────────────────
    print(f"\n[*] Holding for {START_SPAM_DURATION}s "
          f"(match loading → glory point registration) …")
    for elapsed in range(START_SPAM_DURATION):
        await _pause_check()
        if _stop_event.is_set():
            break
        # Send periodic keep-alive during match hold to stay connected
        if elapsed > 0 and elapsed % 8 == 0:
            for b in bots:
                await b.send_online(b'\x00\x00')
        await asyncio.sleep(1)
        print(f"    ⏱  {elapsed + 1}/{START_SPAM_DURATION}s", end='\r', flush=True)
    print()

    # ── All accounts back out ─────────────────────────────────────────────────
    print(f"\n[*] Backing out all {MAX_ACCOUNTS} bots …")
    for bot in bots:
        await bot.leave()
        await asyncio.sleep(BACKOUT_DELAY)

    print(f"\n✅  All bots backed out successfully.")
    print("🏆  Glory points will be credited within ~30 seconds.\n")

    # ── 10. Wait briefly for server-side credit before checking ───────────────
    print("[*] Waiting 35 s for glory point credit to register …")
    for i in range(35):
        await _pause_check()
        if _stop_event.is_set():
            break
        await asyncio.sleep(1)
        print(f"    ⏳  {i + 1}/35s", end='\r', flush=True)
    print()

    # ── 11. Disconnect ────────────────────────────────────────────────────────
    for bot in bots:
        await bot.disconnect()

    # ── 12. Take AFTER glory snapshots for each bot ───────────────────────────
    print("[*] Glory Monitor — taking AFTER snapshots …")
    await asyncio.gather(*[
        glory_monitor.snapshot(b.index, b.account_uid or b.uid, b.token, label='after')
        for b in bots
    ])

    # ── 13. Print glory monitor report ────────────────────────────────────────
    glory_monitor.report(bots)

    print(separator)
    print("  Session complete.  Check in-game for glory point credit.")
    print(separator)


# ═══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE CONSOLE CONTROLLER
# ═══════════════════════════════════════════════════════════════════════════════

# Global control flags
_stop_event   = asyncio.Event()   # set → stop after current session
_pause_event  = asyncio.Event()   # set → bot is PAUSED (session waits)
_start_event  = asyncio.Event()   # set → user said "go"

_bot_running  = False             # True while a session is active


def _print_controls():
    print("\n┌─────────────────────────────────────┐")
    print("│   GR GLORY BOT — Controls            │")
    print("│   [S] Start     [P] Pause/Resume      │")
    print("│   [X] Stop      [Q] Quit              │")
    print("└─────────────────────────────────────┘")
    print("  Enter command: ", end='', flush=True)


async def _input_listener():
    """Background task: read single-letter commands from stdin."""
    global _bot_running, GUILD_ID

    loop = asyncio.get_running_loop()

    while True:
        try:
            raw = await loop.run_in_executor(None, input)
            cmd = raw.strip().upper()
        except (EOFError, KeyboardInterrupt):
            _stop_event.set()
            break

        if cmd == 'S':
            if _bot_running:
                print("[Console] ⚠️  Bot is already running.")
            else:
                if _pause_event.is_set():
                    _pause_event.clear()
                _start_event.set()
                print("[Console] ▶️  Starting bots …")

        elif cmd == 'P':
            if not _bot_running:
                print("[Console] ⚠️  Bot is not running.")
            elif _pause_event.is_set():
                _pause_event.clear()
                print("[Console] ▶️  Resumed.")
            else:
                _pause_event.set()
                print("[Console] ⏸️  Paused — press P again to resume.")

        elif cmd in ('X', 'Q'):
            print("[Console] 🛑  Stop requested — finishing current step …")
            _stop_event.set()
            _start_event.set()   # unblock any wait
            _pause_event.clear()
            break

        elif cmd == '':
            pass  # ignore blank enter

        else:
            print(f"[Console] Unknown command '{cmd}'.  Use S / P / X / Q.")

        if not _stop_event.is_set():
            _print_controls()


async def _pause_check():
    """Call inside long loops to honour the pause flag."""
    while _pause_event.is_set():
        await asyncio.sleep(0.5)


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════
async def main():
    global GUILD_ID, _bot_running

    sep = "═" * 60
    loop = asyncio.get_running_loop()

    print(f"\n{sep}")
    print("    GR GLORY BOT  ·  4-Account Squad Runner  ·  PK")
    print(f"{sep}\n")

    # ── Guild ID setup ────────────────────────────────────────────────────────
    if GUILD_ID is None:
        print("  ⚠️  No Guild ID is set.")
        print("  ┌────────────────────────────────────────────────┐")
        print("  │  Insert Guild ID (numeric) then press Enter:   │")
        print("  └────────────────────────────────────────────────┘")
        print("  > ", end='', flush=True)
        while True:
            try:
                raw = await loop.run_in_executor(None, input)
                gid = raw.strip()
                if gid.isdigit():
                    GUILD_ID = int(gid)
                    print(f"  ✅  Guild ID set to {GUILD_ID}\n")
                    break
                else:
                    print("  ❌  Please enter a valid numeric Guild ID.")
                    print("  > ", end='', flush=True)
            except (EOFError, KeyboardInterrupt):
                print("\n🛑  Cancelled.")
                return

    # ── Load or generate accounts ──────────────────────────────────────────────
    raw = load_accounts(BOT_FILE)
    if len(raw) >= MAX_ACCOUNTS:
        print(f"  ✅  Found {len(raw)} account(s) in {BOT_FILE} — skipping generation.\n")
    else:
        print(f"  ℹ️  {BOT_FILE} has {len(raw)}/{MAX_ACCOUNTS} accounts — generating the rest …\n")
        raw = await generate_guest_accounts(BOT_FILE, MAX_ACCOUNTS)
        if len(raw) < MAX_ACCOUNTS:
            print(f"\n❌  Could not generate {MAX_ACCOUNTS} guest accounts.  Aborting.\n")
            return

    bots: list[BotAccount] = [
        BotAccount(a['uid'], a['password'], i)
        for i, a in enumerate(raw[:MAX_ACCOUNTS])
    ]

    print(f"  Guild ID : {GUILD_ID}")
    print(f"  Region   : {REGION}")
    print(f"  Accounts : {BOT_FILE}")
    print(f"  Bots     : {', '.join(b.bot_label for b in bots)}\n")

    # ── PHASE 1: Startup — runs automatically (no S needed) ───────────────────
    glory_monitor = GloryMonitor()
    ready = await startup_phase(bots, glory_monitor)
    if not ready:
        print("\n❌  Startup failed.  Fix the errors above and restart.")
        return

    # ── Start input listener in background ────────────────────────────────────
    listener_task = asyncio.create_task(_input_listener())

    # ── PHASE 2: Glory farming — each S press runs one glory session ──────────
    print(f"\n{sep}")
    print("  Bots are online in-game and guild requests have been sent.")
    print("  Accept the guild requests in-game, then press [S] to start")
    print("  glory farming.  Press [X] or [Q] to quit.")
    print(f"{sep}\n")
    _print_controls()

    session_count = 0

    while not _stop_event.is_set():
        # Wait for S (or stop)
        await _start_event.wait()
        if _stop_event.is_set():
            break

        session_count += 1
        _bot_running = True
        _start_event.clear()

        print(f"\n{sep}")
        print(f"  GLORY SESSION #{session_count}")
        print(f"{sep}\n")

        try:
            await asyncio.wait_for(
                glory_session(bots, glory_monitor), timeout=7 * 60 * 60
            )
        except asyncio.TimeoutError:
            print("⏰  Session timeout.")
        except asyncio.CancelledError:
            print("\n🛑  Session cancelled.")
            break
        except Exception as exc:
            print(f"\n⚠️   Unexpected error: {exc}")
            traceback.print_exc()
            print("    Waiting 10 s before next session …\n")
            for _ in range(10):
                if _stop_event.is_set():
                    break
                await asyncio.sleep(1)
        finally:
            _bot_running = False

        if _stop_event.is_set():
            break

        print("\n[Console] Session done.  Press [S] to run another, [X] to quit.")
        _print_controls()

    listener_task.cancel()
    # Cleanly disconnect all bots on exit
    for b in bots:
        await b.disconnect()
    print("\n🏁  GR GLORY BOT — Exited.\n")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑  Interrupted.")
