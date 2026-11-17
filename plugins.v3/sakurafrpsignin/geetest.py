"""
GeeTest v3 验证码协议助手（纯 HTTP 实现）

SakuraFrp 每日签到在提交 `/cgi/v4/user/sign` 前需要先通过 GeeTest v3 的人机校验。
本项目仅实现「协议握手」流程：多数情况下第一轮 ajax 交互即可直接拿到 validate，
无需识图；若服务端返回 `result == "click"`（九宫格点选），本轮视为失败并由上层
重试（换新 challenge），重试几次通常可以命中直接放行的情况。

实现参考（MIT License）：
- https://github.com/claaudy/sakurafrp-auto-sign
- https://github.com/zjwzhuzhu/frp-autosign (natfrp/geetest_crack.py)

本文件只做最小化裁剪，将 httpx 换成 requests，去除了图片识别相关逻辑，
并接入 MoviePilot 的 logger。
"""

import hashlib
import json
import math
import random
import time
from urllib.parse import urlencode

import requests


# GeeTest 固定的 RSA 公钥（其前端 JS 中硬编码）
_GEETEST_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDB45NNFhRGWzMFPn9I7k7IexS5
XviJR3E9Je7L/350x5d9AtwdlFH3ndXRwQwprLaptNb7fQoCebZxnhdyVl8Jr2J3
FZGSIa75GJnK4IwNaG10iyCjYDviMYymvCtZcGWSqSGdC/Bcn2UCOiHSMwgHJSrg
Bm1Zzu+l8nSOqAurgQIDAQAB
-----END PUBLIC KEY-----"""

_DEFAULT_MOUSE_PATH = [
    ["move", 385, 313, 1724572150164, "pointermove"],
    ["move", 385, 315, 1724572150166, "pointermove"],
    ["move", 386, 315, 1724572150174, "pointermove"],
    ["move", 387, 315, 1724572150182, "pointermove"],
    ["move", 387, 316, 1724572150188, "pointermove"],
    ["move", 388, 316, 1724572150204, "pointermove"],
    ["move", 388, 317, 1724572150218, "pointermove"],
    ["down", 388, 317, 1724572150586, "pointerdown"],
    ["focus", 1724572150587],
    ["up", 388, 317, 1724572150632, "pointerup"],
]


class GeeTestSolver:
    """GeeTest v3 协议握手，只负责拿到 validate。"""

    def __init__(self, gt: str, challenge: str, referer: str = "https://www.natfrp.com/user/",
                 logger=None, timeout: int = 30):
        self.gt = gt
        self.challenge = challenge
        self.referer = referer
        self.logger = logger
        self.timeout = timeout

        self.c = None
        self.s = None
        self.pic_path = None
        self.last_ajax = None

        self.ajax_host = "https://api.geevisit.com"
        self.get_php_host = "https://api.geetest.com"

        # 每次会话随机生成 AES key
        self.aeskey = "".join(
            f"{int((1 + random.random()) * 65536):04x}"[1:] for _ in range(4)
        )

        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

            pub = serialization.load_pem_public_key(_GEETEST_PUBLIC_KEY_PEM.encode())
            self.enc_key = pub.encrypt(self.aeskey.encode(), PKCS1v15()).hex()
        except Exception as exc:  # pragma: no cover - 依赖缺失时给出明确提示
            raise RuntimeError(
                "缺少 cryptography 依赖，无法完成 GeeTest 校验：%s" % exc
            ) from exc

        self.mouse_path = _DEFAULT_MOUSE_PATH

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            ),
            "Referer": self.referer,
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })

    # ── 编码工具 ────────────────────────────────────────────
    @staticmethod
    def encode(input_bytes: list) -> str:
        def get_char_from_index(index):
            table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()"
            return table[index] if 0 <= index < len(table) else "."

        def transform_value(value, bit_mask):
            result = 0
            for r in range(23, -1, -1):
                if (bit_mask >> r) & 1:
                    result = (result << 1) + ((value >> r) & 1)
            return result

        encoded_string = ""
        pad = ""
        input_length = len(input_bytes)
        for i in range(0, input_length, 3):
            chunk_length = min(3, input_length - i)
            chunk = input_bytes[i: i + chunk_length]
            if chunk_length == 3:
                value = (chunk[0] << 16) + (chunk[1] << 8) + chunk[2]
                encoded_string += (
                    get_char_from_index(transform_value(value, 7274496))
                    + get_char_from_index(transform_value(value, 9483264))
                    + get_char_from_index(transform_value(value, 19220))
                    + get_char_from_index(transform_value(value, 235))
                )
            elif chunk_length == 2:
                value = (chunk[0] << 16) + (chunk[1] << 8)
                encoded_string += (
                    get_char_from_index(transform_value(value, 7274496))
                    + get_char_from_index(transform_value(value, 9483264))
                    + get_char_from_index(transform_value(value, 19220))
                )
                pad = "."
            elif chunk_length == 1:
                value = chunk[0] << 16
                encoded_string += (
                    get_char_from_index(transform_value(value, 7274496))
                    + get_char_from_index(transform_value(value, 9483264))
                )
                pad = ".."
        return encoded_string + pad

    @staticmethod
    def md5(text: str) -> str:
        return hashlib.md5(text.encode()).hexdigest()

    @staticmethod
    def encode_mouse_path(path: list, c: list, s: str) -> str:
        def preprocess(path: list):
            def BFIQ(e):
                t = 32767
                if not isinstance(e, int):
                    return e
                if t < e:
                    e = t
                elif e < -t:
                    e = -t
                return round(e)

            def BGAB(e):
                t = ""
                n = 0
                while n < len(e) and not t:
                    if e[n]:
                        t = e[n][4]
                    n += 1
                if not t:
                    return e
                r = ""
                for prefix in ("mouse", "touch", "pointer", "MSPointer"):
                    if t.startswith(prefix):
                        r = prefix
                _ = list(e)
                for a in range(len(_) - 1, -1, -1):
                    item = _[a]
                    if item[0] in ("move", "down", "up"):
                        value = item[4] or ""
                        if not value.startswith(r):
                            _.pop(a)
                return _

            t = 0
            n = 0
            r = []
            s_val = 0
            if len(path) <= 0:
                return []
            o = None
            a = BGAB(path)
            c_len = len(a)
            for l in range(0 if c_len < 300 else c_len - 300, c_len):
                u = a[l]
                h = u[0]
                if h in ("down", "move", "up", "scroll"):
                    if not o:
                        o = u
                    r.append([h, [u[1] - t, u[2] - n], BFIQ(u[3] - s_val if s_val else s_val)])
                    t = u[1]
                    n = u[2]
                    s_val = u[3]
                elif h in ("blur", "focus", "unload"):
                    r.append([h, BFIQ(u[1] - s_val if s_val else s_val)])
                    s_val = u[1]
            return r

        def process(prepared_path: list):
            h = {"move": 0, "down": 1, "up": 2, "scroll": 3,
                 "focus": 4, "blur": 5, "unload": 6, "unknown": 7}

            def p(e, t):
                n = bin(e)[2:]
                r = ""
                i = len(n) + 1
                while i <= t:
                    i += 1
                    r += "0"
                return r + n

            def d(e):
                t = []
                n = len(e)
                r = 0
                while r < n:
                    i = e[r]
                    s = 0
                    while True:
                        if s >= 16:
                            break
                        o = r + s + 1
                        if o >= n:
                            break
                        if e[o] != i:
                            break
                        s += 1
                    r += 1 + s
                    _ = h[i]
                    if s != 0:
                        t.append(_ | 8)
                        t.append(s - 1)
                    else:
                        t.append(_)
                a = p(n | 32768, 16)
                c = ""
                for l in range(len(t)):
                    c += p(t[l], 4)
                return a + c

            def g(e, tt):
                def temp1(e1):
                    n = len(e1)
                    r = 0
                    i = []
                    while r < n:
                        s = 1
                        o = e1[r]
                        _ = abs(o)
                        while True:
                            if n <= r + s:
                                break
                            if e1[r + s] != o:
                                break
                            if (_ >= 127) or (s >= 127):
                                break
                            s += 1
                        if s > 1:
                            i.append((49152 if o < 0 else 32768) | s << 7 | _)
                        else:
                            i.append(o)
                        r += s
                    return i

                e = temp1(e)
                r = []
                i = []

                def n(e, t):
                    return 0 if e == 0 else math.log(e) / math.log(t)

                for temp in e:
                    t = math.ceil(n(abs(temp) + 1, 16))
                    if t == 0:
                        t = 1
                    r.append(p(t - 1, 2))
                    i.append(p(abs(temp), t * 4))

                s = "".join(r)
                o = "".join(i)

                def temp2(t):
                    return t != 0 and t >> 15 != 1

                def temp3(e1):
                    n = []
                    for r in range(len(e1)):
                        if temp2(e1[r]):
                            n.append("1" if e1[r] < 0 else "0")
                    return "".join(n)

                n_str = temp3(e) if tt else ""
                return p(len(e) | 32768, 16) + s + o + n_str

            def u(e):
                t = ""
                n = len(e) // 6
                charset = "()*,-./0123456789:?@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
                for r in range(n):
                    t += charset[int(e[6 * r: 6 * (r + 1)], 2)]
                return t

            t = []
            n = []
            r = []
            i = []
            for _ in prepared_path:
                a_len = len(_)
                t.append(_[0])
                n.append(_[1] if a_len == 2 else _[2])
                if a_len == 3:
                    r.append(_[1][0])
                    i.append(_[1][1])
            c = d(t) + g(n, False) + g(r, True) + g(i, True)
            l = len(c)
            if l % 6 != 0:
                c += p(0, 6 - l % 6)
            return u(c)

        def postprocess(e, t, n):
            i = 0
            s = e
            o = t[0]
            _ = t[2]
            a = t[4]
            while True:
                r = n[i: i + 2]
                if not r:
                    break
                i += 2
                c = int(r, 16)
                l = chr(c)
                u = (o * c * c + _ * c + a) % len(e)
                s = s[:u] + l + s[u:]
            return s

        return postprocess(process(preprocess(path)), c, s)

    def aes_encrypt(self, content: str) -> bytes:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding

        cipher = Cipher(algorithms.AES(self.aeskey.encode()), modes.CBC(b"0000000000000000"))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded = padder.update(content.encode()) + padder.finalize()
        return encryptor.update(padded) + encryptor.finalize()

    # ── 协议流程 ────────────────────────────────────────────
    def _build_url(self, base_url: str, params: dict) -> str:
        normalized = {}
        for key, value in params.items():
            if isinstance(value, bool):
                normalized[key] = "true" if value else "false"
            else:
                normalized[key] = value
        return f"{base_url}?{urlencode(normalized)}"

    @staticmethod
    def _parse_jsonp(text: str) -> dict:
        left = text.find("(")
        right = text.rfind(")")
        if left != -1 and right != -1 and right > left:
            return json.loads(text[left + 1: right])
        return json.loads(text)

    def _apply_geetest_hosts(self, data) -> None:
        if not isinstance(data, dict):
            return
        api_server = data.get("api_server")
        if isinstance(api_server, str) and api_server:
            api_server = api_server.strip().rstrip("/")
            if not api_server.startswith("http"):
                api_server = f"https://{api_server}"
            self.ajax_host = api_server
            self.get_php_host = api_server.replace("api.geevisit.com", "api.geetest.com")

    def get_type(self) -> dict:
        params = {
            "gt": self.gt,
            "callback": "geetest_" + str(int(round(time.time() * 1000))),
        }
        url = self._build_url("https://api.geetest.com/gettype.php", params)
        resp = self.session.get(url, timeout=self.timeout)
        parsed = self._parse_jsonp(resp.text)
        return parsed["data"]

    def get_c_s(self):
        o = {
            "gt": self.gt,
            "challenge": self.challenge,
            "offline": False,
            "new_captcha": True,
            "product": "float",
            "width": "100%",
            "https": True,
            "protocol": "https://",
        }
        o.update(self.get_type())
        o.update({"cc": 16, "ww": True, "i": "-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1!!-1"})
        o = json.dumps(o, separators=(",", ":"))
        ct = self.aes_encrypt(o)
        i = self.encode(list(ct))
        w = i + self.enc_key
        params = {
            "gt": self.gt,
            "challenge": self.challenge,
            "lang": "zh-cn",
            "pt": 0,
            "client_type": "web",
            "callback": "geetest_" + str(int(round(time.time() * 1000))),
            "w": w,
        }
        url = self._build_url("https://api.geetest.com/get.php", params)
        resp = self.session.get(url, timeout=self.timeout).text
        parsed = self._parse_jsonp(resp)
        if "data" not in parsed:
            raise RuntimeError(f"get_c_s failed: {str(parsed)[:200]}")
        data = parsed["data"]
        self._apply_geetest_hosts(data)
        self.c = data["c"]
        self.s = data["s"]
        return data["c"], data["s"]

    def ajax(self) -> dict:
        def transform(e, t, n):
            if not t or not n:
                return e
            o = 0
            i = list(e)
            s = t[0]
            a = t[2]
            b = t[4]
            while o < len(n):
                r = n[o: o + 2]
                o += 2
                c = int(r, 16)
                l = chr(c)
                u = (s * c * c + a * c + b) % len(i)
                i.insert(u, l)
            return "".join(i)

        tt = transform(self.encode_mouse_path(self.mouse_path, self.c, self.s), self.c, self.s)
        rp = self.md5(self.gt + self.challenge + self.s)
        now = int(time.time() * 1000)
        temp1 = (
            '"lang":"zh-cn","type":"fullpage","tt":"%s",'
            '"light":"DIV_0","s":"c7c3e21112fe4f741921cb3e4ff9f7cb",'
            '"h":"321f9af1e098233dbd03f250fd2b5e21","hh":"39bd9cad9e425c3a8f51610fd506e3b3",'
            '"hi":"09eb21b3ae9542a9bc1e8b63b3d9a467","vip_order":-1,"ct":-1,'
            '"ep":{"v":"9.1.9-dbjg5z","te":false,"me":true,"ven":"Google Inc. (Intel)",'
            '"ren":"ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x0000A7A0) Direct3D11 vs_5_0 ps_5_0, D3D11)",'
            '"fp":["scroll",0,1602,%d,null],"lp":["up",386,217,%d,"pointerup"],'
            '"em":{"ph":0,"cp":0,"ek":"11","wd":1,"nt":0,"si":0,"sc":0},'
            '"tm":{"a":%d,"b":%d,"c":%d,"d":0,"e":0,"f":%d,"g":%d,"h":%d,"i":%d,"j":%d,'
            '"k":%d,"l":%d,"m":%d,"n":%d,"o":%d,"p":%d,"q":%d,"r":%d,"s":%d,"t":%d,"u":%d},'
            '"dnf":"dnf","by":0},"passtime":1600,"rp":"%s","'
            % (tt, now - 5000, now - 3000, now - 8000, now - 7970, now - 7960, now - 8000,
               now - 8000, now - 8000, now - 7990, now - 7880, now - 7990, now - 7880,
               now - 7970, now - 7968, now - 7950, now - 7400, now - 7400, now - 5000,
               now - 4000, now - 4000, now - 4000, rp)
        )
        r = "{" + temp1 + '"captcha_token":"1198034057","du6o":"eyjf7nne"}'
        ct = self.aes_encrypt(r)
        w = self.encode([byte for byte in ct])
        params = {
            "gt": self.gt,
            "challenge": self.challenge,
            "lang": "zh-cn",
            "pt": 0,
            "client_type": "web",
            "callback": "geetest_" + str(int(round(time.time() * 1000))),
            "w": w,
        }
        url = self._build_url(f"{self.ajax_host}/ajax.php", params)
        resp = self.session.get(url, timeout=self.timeout).text
        parsed = self._parse_jsonp(resp)
        if "data" not in parsed:
            raise RuntimeError(f"ajax failed: {str(parsed)[:200]}")
        self.last_ajax = parsed["data"]
        return parsed["data"]

    def solve(self) -> str:
        """完整走一轮协议握手，返回 validate；若命中点选验证码返回 None。"""
        self.get_c_s()
        data = self.ajax()
        if data.get("result") == "success" and data.get("validate"):
            return data["validate"]
        return None

    def close(self):
        try:
            self.session.close()
        except Exception:
            pass
