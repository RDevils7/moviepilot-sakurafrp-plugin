"""
SakuraFrp（樱花内网穿透）每日签到 —— MoviePilot V3 插件

功能
----
- 自动完成 SakuraFrp（https://www.natfrp.com）每日签到，领取签到流量
- 支持「账号密码」自动登录（OpenID + GeeTest）或「网页 Cookie」免登录两种方式
- 支持多账号、失败重试、签到记录、结果通知
- 随机错峰：每日在随机时间执行，支持「每月重新随机」避免固定时刻
- 签到流量统计图表（累计流量趋势、连续签到天数趋势）
- 验证码问题连续失败 2 次则当天停止签到，并通过 Telegram 通知
- 支持定时任务（cron）、立即执行一次

说明
----
SakuraFrp 的签到接口 `/cgi/v4/user/sign` 仅接受 SESSION（Cookie）鉴权，
且在提交签到前需要通过 GeeTest v3 人机校验。本插件在提交前会自动完成
GeeTest 协议握手（多数情况下无需识图即可放行）；若持续命中「九宫格点选」，
本轮会失败并在下一轮/次日重试。

签到状态通过 `/cgi/v4/user/info`（SESSION 鉴权）返回的 `sign` 字段判断：
`{"signed": bool, "days": int, "traffic": float, "last": "YYYY-MM-DD"}`。
"""

import random
import re
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin
from zoneinfo import ZoneInfo

import requests
from apscheduler.triggers.cron import CronTrigger

# MoviePilot V3 稳定插件入口：优先 app.sdk，兼容旧版路径
try:
    from app.sdk.plugin import _PluginBase
except Exception:  # pragma: no cover - 兼容 V2 或旧版本
    from app.plugins import _PluginBase

try:
    from app.sdk.logging import logger
except Exception:  # pragma: no cover - 兼容 V2 或旧版本
    from app.log import logger

try:
    from app.schemas.types import NotificationType
except Exception:  # pragma: no cover
    NotificationType = None

try:
    from .geetest import GeeTestSolver
except Exception as _geetest_err:  # pragma: no cover
    GeeTestSolver = None
    _GEETEST_IMPORT_ERROR = _geetest_err


BASE_URL = "https://www.natfrp.com"
OPENID_URL = "https://openid.13a.com"

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

_COMMON_HEADERS = {
    "User-Agent": _UA,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}


class _NatFrpClient:
    """针对 SakuraFrp 面板的最小 HTTP 客户端（统一使用一个 Session 维持 Cookie）。"""

    def __init__(self, timeout: int = 20, proxy: str = ""):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(_COMMON_HEADERS)
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def close(self):
        try:
            self.session.close()
        except Exception:
            pass

    # ── 基础请求 ────────────────────────────────────────────
    def _follow(self, resp: requests.Response, referer: bool = True, max_steps: int = 10):
        """手动跟随重定向（用于 OpenID 登录跳转链）。"""
        step = 0
        while resp.is_redirect and step < max_steps:
            location = resp.headers.get("Location")
            if not location:
                break
            next_url = urljoin(resp.url, location)
            headers = {"Referer": resp.url} if referer else {}
            resp = self.session.get(
                next_url, headers=headers, allow_redirects=False, timeout=self.timeout
            )
            step += 1
        return resp

    def user_info(self) -> Tuple[Dict[str, Any], int]:
        resp = self.session.get(f"{BASE_URL}/cgi/v4/user/info", timeout=self.timeout)
        try:
            return resp.json(), resp.status_code
        except Exception:
            return {"_raw": resp.text[:500]}, resp.status_code

    # ── 登录 ────────────────────────────────────────────────
    def login_by_cookie(self, cookie: str) -> Dict[str, Any]:
        cookie = (cookie or "").strip()
        if not cookie:
            raise RuntimeError("Cookie 为空")
        self.session.headers["Cookie"] = cookie
        info, code = self.user_info()
        if not isinstance(info, dict) or ("name" not in info and "id" not in info):
            raise RuntimeError(f"Cookie 无效或已过期（HTTP {code}）：{str(info)[:200]}")
        return info

    def login_by_password(self, username: str, password: str, solver_factory) -> Dict[str, Any]:
        # 1. 预热会话，让 OpenID 下发必要的 Cookie
        resp = self.session.get(
            f"{BASE_URL}/cgi/user/login", allow_redirects=False, timeout=self.timeout
        )
        self._follow(resp)

        # 2. 取登录验证码并用 GeeTest 协议握手拿到 validate
        validate, challenge = self._solve_openid_captcha(solver_factory)
        if not validate:
            raise RuntimeError("登录验证码需人工点选，自动登录失败，请改用 Cookie 方式")

        # 3. 提交登录
        login_data = {
            "username": username,
            "password": password,
            "geetest_id": challenge,
            "geetest_challenge": challenge,
            "geetest_validate": validate,
            "geetest_seccode": f"{validate}|jordan",
        }
        resp = self.session.post(
            f"{OPENID_URL}/cgi/password/login",
            data=login_data,
            headers={
                "Referer": f"{OPENID_URL}/login",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With": "XMLHttpRequest",
            },
            allow_redirects=False,
            timeout=self.timeout,
        )
        if resp.status_code not in (200, 302):
            raise RuntimeError(f"登录请求失败：HTTP {resp.status_code} {resp.text[:200]}")

        # 4. 完成 OpenID → natfrp 的跳转桥接
        resp = self.session.get(
            f"{OPENID_URL}/redirect",
            headers={"Referer": f"{OPENID_URL}/login"},
            allow_redirects=False,
            timeout=self.timeout,
        )
        self._follow(resp)

        # 5. 校验登录状态
        info, code = self.user_info()
        if not isinstance(info, dict) or ("name" not in info and "id" not in info):
            raise RuntimeError(f"登录校验失败（HTTP {code}）：{str(info)[:200]}")
        return info

    def _solve_openid_captcha(self, solver_factory):
        last_err = None
        for _ in range(3):
            try:
                cap = self.session.get(
                    f"{OPENID_URL}/cgi/captcha?login",
                    headers={
                        "Referer": f"{OPENID_URL}/login",
                        "X-Requested-With": "XMLHttpRequest",
                    },
                    timeout=self.timeout,
                ).json()
            except Exception as exc:
                last_err = exc
                continue
            if not cap.get("success"):
                last_err = RuntimeError(f"获取验证码配置失败：{str(cap)[:200]}")
                continue
            gt = cap["message"]["gt"]
            challenge = cap["message"]["challenge"]
            solver = solver_factory(gt, challenge, f"{OPENID_URL}/")
            try:
                validate = solver.solve()
            finally:
                solver.close()
            if validate:
                return validate, challenge
        if last_err:
            logger.warning(f"SakuraFrp 登录验证码处理失败：{last_err}")
        return None, None

    # ── 签到 ────────────────────────────────────────────────
    def get_sign_challenge(self) -> Tuple[str, str]:
        resp = self.session.get(f"{BASE_URL}/cgi/v4/user/sign?gt", timeout=self.timeout)
        try:
            data = resp.json()
        except Exception:
            match = re.search(r"\((\{.*\})\)", resp.text, re.DOTALL)
            if not match:
                raise RuntimeError(f"无法解析签到验证码数据：{resp.text[:200]}")
            import json as _json

            data = _json.loads(match.group(1))
        if "gt" not in data or "challenge" not in data:
            raise RuntimeError(f"签到验证码数据异常：{str(data)[:200]}")
        return data["gt"], data["challenge"]

    def do_sign(self, solver_factory, retries: int = 3) -> Dict[str, Any]:
        challenge = None
        validate = None
        challenge_ok = False
        captcha_failures = 0
        for round_no in range(1, max(1, retries) + 1):
            try:
                gt, challenge = self.get_sign_challenge()
                challenge_ok = True
            except Exception as exc:
                logger.warning(f"SakuraFrp 获取签到验证码失败（第 {round_no} 次）：{exc}")
                continue
            solver = solver_factory(gt, challenge, f"{BASE_URL}/user/")
            try:
                validate = solver.solve()
            except Exception as exc:
                logger.warning(f"SakuraFrp GeeTest 校验异常（第 {round_no} 次）：{exc}")
                validate = None
            finally:
                solver.close()
            if validate:
                break
            captcha_failures += 1
            logger.info(f"SakuraFrp 签到命中点选验证码，重试新一轮（{round_no}/{retries}）")

        if not validate:
            if captcha_failures > 0:
                msg = f"GeeTest 校验连续失败 {captcha_failures} 次，签到失败"
            else:
                msg = "获取签到验证码失败，签到未执行"
            return {
                "success": False,
                "captcha_error": captcha_failures > 0,
                "captcha_failures": captcha_failures,
                "message": msg,
            }

        headers = dict(_COMMON_HEADERS)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Referer"] = f"{BASE_URL}/user/"
        sign_data = {
            "geetest_challenge": challenge,
            "geetest_validate": validate,
            "geetest_seccode": f"{validate}|jordan",
        }
        resp = self.session.post(
            f"{BASE_URL}/cgi/v4/user/sign",
            data=sign_data,
            headers=headers,
            timeout=self.timeout,
        )
        try:
            result = resp.json()
        except Exception:
            return {"success": False, "message": f"签到返回非 JSON：{resp.text[:200]}"}

        ok = (
            isinstance(result, str)
            or (isinstance(result, dict) and (
                result.get("status") == "success" or result.get("code") == 0
            ))
        )

        # 二次校验签到状态
        extra = {}
        try:
            info, _ = self.user_info()
            sign = (info or {}).get("sign") or {}
            extra = {
                "signed": sign.get("signed"),
                "days": sign.get("days"),
                "traffic": sign.get("traffic"),
                "last": sign.get("last"),
            }
            if sign.get("signed"):
                ok = True
        except Exception as exc:
            logger.warning(f"SakuraFrp 签到后校验状态失败：{exc}")

        return {
            "success": ok,
            "captcha_error": False,
            "captcha_failures": captcha_failures,
            "message": str(result)[:200] if not ok else "签到成功",
            "extra": extra,
        }


class SakuraFrpSignin(_PluginBase):
    """SakuraFrp 每日签到插件"""

    # ── 插件元信息 ──
    plugin_name = "SakuraFrp每日签到"
    plugin_desc = "自动完成 SakuraFrp（樱花内网穿透）每日签到；支持账号密码/Cookie、多账号、随机错峰、流量统计图表，验证码连续失败自动停止并 Telegram 通知。"
    plugin_icon = "https://raw.githubusercontent.com/natfrp/wiki/master/.vuepress/public/favicon.ico"
    plugin_color = "#F472B6"
    plugin_version = "1.1.1"
    plugin_author = "MoviePilot"
    author_url = "https://www.natfrp.com/"
    plugin_config_prefix = "sakurafrsignin_"
    plugin_order = 50
    auth_level = 1

    # ── 默认配置（类属性，避免插件首次安装未保存配置时属性缺失）──
    _enabled: bool = False
    _notify_enabled: bool = True
    _notify_type: str = "Plugin"
    _cron: str = "0 8 * * *"
    _onlyonce: bool = False
    _login_mode: str = "password"
    _accounts: str = ""
    _retry: int = 3
    _timeout: int = 20
    _history_days: int = 30
    _proxy: str = ""
    # 随机错峰
    _random_stagger: bool = True
    _stagger_window: int = 60
    _stagger_monthly: bool = True
    # Telegram 通知
    _telegram_enabled: bool = False
    _telegram_bot_token: str = ""
    _telegram_chat_id: str = ""

    _DATA_KEY = "sign_history"
    _CAPTCHA_STATE_KEY = "captcha_state"
    _STAGGER_KEY = "stagger_state"
    try:
        _TZ = ZoneInfo("Asia/Shanghai")
    except Exception:  # pragma: no cover - 容器缺少 tzdata 时回退
        from datetime import timedelta as _timedelta, timezone as _timezone
        _TZ = _timezone(_timedelta(hours=8))

    # ── 生命周期 ────────────────────────────────────────────
    def init_plugin(self, config: dict = None):
        config = config or {}
        self._enabled = bool(config.get("enabled", False))
        self._notify_enabled = bool(config.get("notify_enabled", True))
        self._notify_type = config.get("notify_type") or "Plugin"
        self._cron = (config.get("cron") or "0 8 * * *").strip()
        self._onlyonce = bool(config.get("onlyonce", False))
        self._login_mode = (config.get("login_mode") or "password").strip()
        self._accounts = config.get("accounts") or ""
        try:
            self._retry = max(1, int(config.get("retry") or 3))
        except (TypeError, ValueError):
            self._retry = 3
        try:
            self._timeout = max(5, int(config.get("timeout") or 20))
        except (TypeError, ValueError):
            self._timeout = 20
        try:
            self._history_days = max(1, int(config.get("history_days") or 30))
        except (TypeError, ValueError):
            self._history_days = 30
        self._proxy = (config.get("proxy") or "").strip()
        # 随机错峰
        self._random_stagger = bool(config.get("random_stagger", True))
        try:
            self._stagger_window = max(0, int(config.get("stagger_window") or 60))
        except (TypeError, ValueError):
            self._stagger_window = 60
        self._stagger_monthly = bool(config.get("stagger_monthly", True))
        # Telegram 通知
        self._telegram_enabled = bool(config.get("telegram_enabled", False))
        self._telegram_bot_token = (config.get("telegram_bot_token") or "").strip()
        self._telegram_chat_id = (config.get("telegram_chat_id") or "").strip()
        if not getattr(self, "_lock", None):
            self._lock = threading.Lock()

        if self._onlyonce:
            logger.info("SakuraFrp每日签到：检测到「立即运行一次」，开始执行")
            self._onlyonce = False
            self._save_config()
            try:
                self._run_all()
            except Exception as exc:
                logger.error(f"SakuraFrp每日签到立即运行失败：{exc}", exc_info=True)

    def _save_config(self):
        self.update_config({
            "enabled": self._enabled,
            "notify_enabled": self._notify_enabled,
            "notify_type": self._notify_type,
            "cron": self._cron,
            "onlyonce": self._onlyonce,
            "login_mode": self._login_mode,
            "accounts": self._accounts,
            "retry": self._retry,
            "timeout": self._timeout,
            "history_days": self._history_days,
            "proxy": self._proxy,
            "random_stagger": self._random_stagger,
            "stagger_window": self._stagger_window,
            "stagger_monthly": self._stagger_monthly,
            "telegram_enabled": self._telegram_enabled,
            "telegram_bot_token": self._telegram_bot_token,
            "telegram_chat_id": self._telegram_chat_id,
        })

    def get_state(self) -> bool:
        return self._enabled

    # ── 表单 / 页面 / 接口 / 服务 ───────────────────────────
    @staticmethod
    def get_command() -> List[Dict[str, Any]]:
        return []

    def get_api(self) -> List[Dict[str, Any]]:
        return [{
            "path": "/run",
            "endpoint": self.api_run_now,
            "methods": ["GET"],
            "summary": "立即执行签到",
            "description": "手动触发一次 SakuraFrp 签到",
        }]

    def api_run_now(self) -> Dict[str, Any]:
        results = self._run_all()
        return {"success": all(r.get("success") for r in results) if results else False,
                "data": results}

    def get_form(self) -> Tuple[List[dict], Dict[str, Any]]:
        msg_options = []
        if NotificationType is not None:
            try:
                msg_options = [{"title": item.value, "value": item.name} for item in NotificationType]
            except Exception:
                msg_options = []
        return [
            {
                "component": "VForm",
                "content": [
                    {
                        "component": "VRow",
                        "content": [
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 3},
                                "content": [{
                                    "component": "VSwitch",
                                    "props": {"model": "enabled", "label": "启用插件"},
                                }],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 3},
                                "content": [{
                                    "component": "VSwitch",
                                    "props": {"model": "onlyonce", "label": "立即运行一次"},
                                }],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 3},
                                "content": [{
                                    "component": "VSwitch",
                                    "props": {"model": "notify_enabled", "label": "发送通知"},
                                }],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 3},
                                "content": [{
                                    "component": "VSelect",
                                    "props": {
                                        "model": "notify_type",
                                        "label": "通知类型",
                                        "items": msg_options,
                                        "clearable": True,
                                    },
                                }],
                            },
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{
                                    "component": "VTextField",
                                    "props": {
                                        "model": "cron",
                                        "label": "签到时间（5 段 cron）",
                                        "placeholder": "0 8 * * *",
                                    },
                                }],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{
                                    "component": "VSelect",
                                    "props": {
                                        "model": "login_mode",
                                        "label": "登录方式",
                                        "items": [
                                            {"title": "账号密码", "value": "password"},
                                            {"title": "网页 Cookie", "value": "cookie"},
                                        ],
                                    },
                                }],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{
                                    "component": "VTextField",
                                    "props": {
                                        "model": "retry",
                                        "label": "验证码重试次数",
                                        "type": "number",
                                        "placeholder": "3",
                                    },
                                }],
                            },
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{
                                    "component": "VTextField",
                                    "props": {
                                        "model": "timeout",
                                        "label": "请求超时（秒）",
                                        "type": "number",
                                        "placeholder": "20",
                                    },
                                }],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{
                                    "component": "VTextField",
                                    "props": {
                                        "model": "history_days",
                                        "label": "记录保留天数",
                                        "type": "number",
                                        "placeholder": "30",
                                    },
                                }],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{
                                    "component": "VTextField",
                                    "props": {
                                        "model": "proxy",
                                        "label": "HTTP(S) 代理（可选）",
                                        "placeholder": "http://127.0.0.1:7890",
                                    },
                                }],
                            },
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{
                                    "component": "VSwitch",
                                    "props": {"model": "random_stagger", "label": "启用随机错峰"},
                                }],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{
                                    "component": "VTextField",
                                    "props": {
                                        "model": "stagger_window",
                                        "label": "错峰窗口（分钟）",
                                        "type": "number",
                                        "placeholder": "60",
                                    },
                                }],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{
                                    "component": "VSwitch",
                                    "props": {"model": "stagger_monthly", "label": "每月重新随机"},
                                }],
                            },
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 3},
                                "content": [{
                                    "component": "VSwitch",
                                    "props": {"model": "telegram_enabled", "label": "Telegram 通知"},
                                }],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 5},
                                "content": [{
                                    "component": "VTextField",
                                    "props": {
                                        "model": "telegram_bot_token",
                                        "label": "Telegram Bot Token",
                                        "placeholder": "123456:ABC-DEF...",
                                    },
                                }],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{
                                    "component": "VTextField",
                                    "props": {
                                        "model": "telegram_chat_id",
                                        "label": "Telegram Chat ID",
                                        "placeholder": "-1001234567890",
                                    },
                                }],
                            },
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [{
                            "component": "VCol",
                            "props": {"cols": 12},
                            "content": [{
                                "component": "VTextarea",
                                "props": {
                                    "model": "accounts",
                                    "label": "账号列表（每行一个账号）",
                                    "rows": 5,
                                    "placeholder": (
                                        "账号密码模式：备注|用户名|密码\n"
                                        "Cookie 模式：备注|PHPSESSID=xxxx（或整段 Cookie）"
                                    ),
                                },
                            }],
                        }],
                    },
                    {
                        "component": "VRow",
                        "content": [{
                            "component": "VCol",
                            "props": {"cols": 12},
                            "content": [{
                                "component": "VAlert",
                                "props": {
                                    "type": "info",
                                    "variant": "tonal",
                                    "text": (
                                        "Cookie 获取方法：浏览器登录 natfrp.com 后，打开开发者工具 → "
                                        "Application/网络 → 复制 Cookie 中的 PHPSESSID（或整段 Cookie）。"
                                        "Cookie 会过期，失效后请及时更新；账号密码方式会自动完成 GeeTest "
                                        "协议校验，但可能受风控影响。签到记录最多保存 30 条。"
                                    ),
                                },
                            }],
                        }],
                    },
                ],
            }
        ], {
            "enabled": False,
            "onlyonce": False,
            "notify_enabled": True,
            "notify_type": "Plugin",
            "cron": "0 8 * * *",
            "login_mode": "password",
            "retry": 3,
            "timeout": 20,
            "history_days": 30,
            "proxy": "",
            "random_stagger": True,
            "stagger_window": 60,
            "stagger_monthly": True,
            "telegram_enabled": False,
            "telegram_bot_token": "",
            "telegram_chat_id": "",
            "accounts": "",
        }

    def get_page(self) -> Optional[List[dict]]:
        history: List[Dict[str, Any]] = self.get_data(self._DATA_KEY) or []
        if not history:
            return [{
                "component": "VAlert",
                "props": {
                    "type": "info",
                    "variant": "tonal",
                    "text": "暂无签到记录。启用插件并保存后，可在配置页勾选「立即运行一次」，"
                            "或等待定时任务执行后在此查看记录。",
                },
            }]

        page: List[dict] = []

        # 流量/天数统计图表
        charts = self._build_charts(history)
        if charts:
            page.append({"component": "VRow", "content": charts})

        # 概要
        dates = sorted({(r.get("time") or "")[:10] for r in history if (r.get("time") or "")[:10]})
        last = history[-1] if history else {}
        page.append({
            "component": "VAlert",
            "props": {
                "type": "success",
                "variant": "tonal",
                "text": (
                    f"共 {len(dates)} 天有签到记录；最近一次连续签到 {last.get('days', '?')} 天；"
                    f"当前累计签到流量 {last.get('traffic', '?')}（单位以站点为准）。"
                ),
            },
        })

        headers = [
            {"title": "时间", "key": "time"},
            {"title": "账号", "key": "account"},
            {"title": "结果", "key": "result"},
            {"title": "连续天数", "key": "days"},
            {"title": "累计流量", "key": "traffic"},
            {"title": "说明", "key": "message"},
        ]
        items = []
        for rec in reversed(history[-100:]):
            items.append({
                "time": rec.get("time", ""),
                "account": rec.get("account", ""),
                "result": "✅ 成功" if rec.get("success") else "❌ 失败",
                "days": rec.get("days", ""),
                "traffic": rec.get("traffic", ""),
                "message": rec.get("message", ""),
            })
        page.append({
            "component": "VDataTable",
            "props": {
                "headers": headers,
                "items": items,
                "density": "compact",
                "hide-default-footer": True,
                "items-per-page": 100,
            },
        })
        return page

    def _build_charts(self, history: List[Dict[str, Any]]) -> List[dict]:
        """根据历史记录构建「签到流量」「连续天数」折线图。"""
        traffic_by_date: Dict[str, float] = {}
        days_by_date: Dict[str, int] = {}
        for rec in history:
            d = (rec.get("time") or "")[:10]
            if not d:
                continue
            try:
                traffic_by_date[d] = float(rec.get("traffic"))
            except (TypeError, ValueError):
                pass
            try:
                days_by_date[d] = int(rec.get("days"))
            except (TypeError, ValueError):
                pass

        dates = sorted(set(list(traffic_by_date.keys()) + list(days_by_date.keys())))
        if len(dates) < 2:
            return []
        traffic_series = [traffic_by_date.get(d) for d in dates]
        days_series = [days_by_date.get(d) for d in dates]

        def line_chart(title: str, series: List[dict], y_title: str) -> dict:
            return {
                "component": "VCol",
                "props": {"cols": 12, "md": 6},
                "content": [{
                    "component": "VApexChart",
                    "props": {
                        "height": 300,
                        "options": {
                            "chart": {"type": "line", "zoom": {"enabled": True}},
                            "title": {"text": title},
                            "xaxis": {"categories": dates},
                            "stroke": {"curve": "smooth", "width": 2},
                            "markers": {"size": 3},
                            "legend": {"show": True},
                            "tooltip": {"shared": True},
                            "dataLabels": {"enabled": False},
                            "noData": {"text": "暂无数据"},
                            "yaxis": {"title": {"text": y_title}},
                        },
                        "series": series,
                    },
                }],
            }

        charts: List[dict] = []
        if any(v is not None for v in traffic_series):
            charts.append(line_chart(
                "签到累计流量趋势（GB）",
                [{"name": "签到累计流量", "data": traffic_series}], "GB",
            ))
        if any(v is not None for v in days_series):
            charts.append(line_chart(
                "连续签到天数趋势",
                [{"name": "连续签到天数", "data": days_series}], "天",
            ))
        return charts

    def get_service(self) -> List[Dict[str, Any]]:
        if not self._enabled or not self._cron:
            return []
        try:
            trigger = CronTrigger.from_crontab(self._cron, timezone=self._TZ)
        except Exception as exc:
            logger.error(f"SakuraFrp每日签到：cron 表达式非法 [{self._cron}]：{exc}，回退到 0 8 * * *")
            trigger = CronTrigger.from_crontab("0 8 * * *", timezone=self._TZ)
        return [{
            "id": "SakuraFrpSignin",
            "name": "SakuraFrp每日签到",
            "trigger": trigger,
            "func": self._staggered_entry,
            "kwargs": {},
        }]

    def stop_service(self):
        pass

    # ── 核心逻辑 ────────────────────────────────────────────
    def _parse_accounts(self) -> List[Dict[str, str]]:
        accounts: List[Dict[str, str]] = []
        for raw in (self._accounts or "").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if self._login_mode == "password":
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 3:
                    label, username, password = parts[0], parts[1], parts[2]
                elif len(parts) == 2:
                    label, username, password = "", parts[0], parts[1]
                else:
                    logger.warning(f"SakuraFrp每日签到：忽略格式不正确的账号行：{line[:30]}")
                    continue
                if not username or not password:
                    continue
                accounts.append({
                    "label": label or username,
                    "username": username,
                    "password": password,
                })
            else:  # cookie
                parts = [p.strip() for p in line.split("|", 1)]
                if len(parts) == 2:
                    label, cookie = parts[0], parts[1]
                else:
                    label, cookie = "", parts[0]
                if not cookie:
                    continue
                accounts.append({
                    "label": label or f"账号{len(accounts) + 1}",
                    "cookie": cookie,
                })
        return accounts

    def _solver_factory(self, gt: str, challenge: str, referer: str):
        if GeeTestSolver is None:
            raise RuntimeError(f"缺少 GeeTest 依赖：{_GEETEST_IMPORT_ERROR}")
        return GeeTestSolver(
            gt=gt, challenge=challenge, referer=referer, logger=logger, timeout=self._timeout
        )

    def _signin_account(self, account: Dict[str, str], max_rounds: Optional[int] = None) -> Dict[str, Any]:
        rounds = max_rounds if max_rounds else self._retry
        client = _NatFrpClient(timeout=self._timeout, proxy=self._proxy)
        try:
            if "cookie" in account:
                info = client.login_by_cookie(account["cookie"])
            else:
                info = client.login_by_password(
                    account["username"], account["password"], self._solver_factory
                )
            name = info.get("name", account.get("label", "未知用户"))
            sign = info.get("sign") or {}
            if sign.get("signed"):
                return {
                    "success": True,
                    "captcha_error": False,
                    "captcha_failures": 0,
                    "message": f"今日已签到（连续 {sign.get('days', '?')} 天）",
                    "days": sign.get("days", ""),
                    "traffic": sign.get("traffic", ""),
                    "user": name,
                }
            result = client.do_sign(self._solver_factory, retries=rounds)
            extra = result.get("extra") or {}
            return {
                "success": bool(result.get("success")),
                "captcha_error": bool(result.get("captcha_error")),
                "captcha_failures": int(result.get("captcha_failures") or 0),
                "message": result.get("message", ""),
                "days": extra.get("days", sign.get("days", "")),
                "traffic": extra.get("traffic", sign.get("traffic", "")),
                "user": name,
            }
        finally:
            client.close()

    def _run_all(self) -> List[Dict[str, Any]]:
        if not getattr(self, "_lock", None):
            self._lock = threading.Lock()
        if not self._lock.acquire(blocking=False):
            logger.warning("SakuraFrp每日签到：已有任务在执行，跳过本次")
            return []
        try:
            return self._run_all_inner()
        finally:
            self._lock.release()

    def _run_all_inner(self) -> List[Dict[str, Any]]:
        accounts = self._parse_accounts()
        if not accounts:
            logger.warning("SakuraFrp每日签到：未配置任何账号，跳过执行")
            return []

        today = datetime.now(self._TZ).strftime("%Y-%m-%d")
        state = self.get_data(self._CAPTCHA_STATE_KEY) or {}
        if not isinstance(state, dict) or state.get("date") != today:
            state = {"date": today, "count": 0, "stopped": False}
        if state.get("stopped"):
            logger.warning(
                f"SakuraFrp每日签到：今日（{today}）因验证码连续失败已停止签到，本次跳过"
            )
            return []

        results: List[Dict[str, Any]] = []
        now_str = datetime.now(self._TZ).strftime("%Y-%m-%d %H:%M:%S")
        stopped_now = False
        max_captcha_fails = 2
        for account in accounts:
            label = account.get("label", "账号")
            allowed = max_captcha_fails - int(state.get("count", 0))
            if allowed <= 0:
                state["stopped"] = True
                stopped_now = True
                break
            logger.info(
                f"SakuraFrp每日签到：开始处理账号 [{label}]（今日剩余验证码容错 {allowed} 次）"
            )
            try:
                res = self._signin_account(account, max_rounds=min(self._retry, allowed))
            except Exception as exc:
                msg = str(exc)
                logger.error(f"SakuraFrp每日签到：账号 [{label}] 执行异常：{msg}", exc_info=True)
                captcha_like = ("验证码" in msg) or ("geetest" in msg.lower())
                res = {"success": False, "message": msg[:200], "days": "", "traffic": "",
                       "captcha_error": captcha_like, "captcha_failures": 1 if captcha_like else 0}
            res["account"] = label
            res["time"] = now_str
            res["captcha_error"] = bool(res.get("captcha_error"))
            results.append(res)
            logger.info(
                f"SakuraFrp每日签到：账号 [{label}] "
                f"{'成功' if res.get('success') else '失败'} - {res.get('message', '')}"
            )

            # 验证码问题累计失败达到上限（默认 2 次）→ 当天停止
            if (not res.get("success")) and res.get("captcha_error"):
                fails = int(res.get("captcha_failures") or 1)
                state["count"] = int(state.get("count", 0)) + fails
                if state["count"] >= max_captcha_fails:
                    state["stopped"] = True
                    stopped_now = True
                    self.save_data(self._CAPTCHA_STATE_KEY, state)
                    logger.warning(
                        f"SakuraFrp每日签到：今日验证码累计失败 {state['count']} 次，"
                        f"停止今日（{today}）剩余签到"
                    )
                    break

        self.save_data(self._CAPTCHA_STATE_KEY, state)
        self._save_history(results, now_str)
        self._notify(results)
        if stopped_now:
            self._notify_captcha_stop(today, results)
        return results

    # ── 随机错峰 ────────────────────────────────────────────
    def _staggered_entry(self):
        """定时任务入口：启用随机错峰时按随机延迟执行。"""
        try:
            delay = self._compute_stagger_delay()
        except Exception as exc:
            logger.warning(f"SakuraFrp每日签到：计算随机错峰失败，立即执行：{exc}")
            delay = 0
        if delay <= 0:
            return self._run_all()
        logger.info(f"SakuraFrp每日签到：随机错峰延迟 {delay} 秒后执行签到")
        threading.Thread(target=self._delayed_run, args=(delay,), daemon=True).start()
        return None

    def _delayed_run(self, delay: int):
        try:
            time.sleep(delay)
        except Exception:
            pass
        try:
            self._run_all()
        except Exception as exc:
            logger.error(f"SakuraFrp每日签到：延迟执行失败：{exc}", exc_info=True)

    def _compute_stagger_delay(self) -> int:
        """返回本次执行的随机延迟秒数。

        - 未启用或窗口 <= 0：返回 0
        - 未开启「每月重新随机」：每次随机 [0, 窗口]
        - 开启「每月重新随机」：每个自然月生成一个固定基准偏移（保存在 stagger_state），
          每天再叠加一个小抖动，做到「每月错峰、每天不完全同一时刻」。
        """
        if not self._random_stagger or self._stagger_window <= 0:
            return 0
        window = self._stagger_window * 60
        if not self._stagger_monthly:
            return random.randint(0, window)
        month_key = datetime.now(self._TZ).strftime("%Y-%m")
        state = self.get_data(self._STAGGER_KEY) or {}
        if not isinstance(state, dict) or state.get("month") != month_key:
            state = {"month": month_key, "offset": random.randint(0, window)}
            self.save_data(self._STAGGER_KEY, state)
        base = int(state.get("offset", 0) or 0)
        jitter = random.randint(0, min(300, max(0, window // 10)))
        return min(window, base + jitter)

    # ── Telegram 通知 ───────────────────────────────────────
    def _send_telegram(self, text: str) -> bool:
        if not (self._telegram_enabled and self._telegram_bot_token and self._telegram_chat_id):
            return False
        url = f"https://api.telegram.org/bot{self._telegram_bot_token}/sendMessage"
        payload = {
            "chat_id": self._telegram_chat_id,
            "text": text,
            "disable_web_page_preview": True,
        }
        proxies = None
        if self._proxy:
            proxies = {"http": self._proxy, "https": self._proxy}
        try:
            resp = requests.post(url, json=payload, timeout=self._timeout, proxies=proxies)
            data = resp.json()
            if not data.get("ok"):
                logger.error(f"SakuraFrp每日签到：Telegram 发送失败：{str(data)[:200]}")
                return False
            logger.info("SakuraFrp每日签到：Telegram 通知已发送")
            return True
        except Exception as exc:
            logger.error(f"SakuraFrp每日签到：Telegram 发送异常：{exc}")
            return False

    def _notify_captcha_stop(self, date: str, results: List[Dict[str, Any]]):
        lines = [f"⚠️ SakuraFrp 签到因验证码问题连续失败 2 次，已停止今日（{date}）后续签到。"]
        for r in results:
            icon = "✅" if r.get("success") else "❌"
            lines.append(f"{icon} {r.get('account')}：{r.get('message', '')}")
        lines.append("可稍后点击「立即运行一次」手动重试，或等待明天定时任务。")
        text = "\n".join(lines)
        logger.warning(text)
        sent = self._send_telegram(text)
        if not sent and self._notify_enabled:
            try:
                if NotificationType is not None:
                    self.post_message(mtype=NotificationType.Plugin,
                                      title="⚠️ SakuraFrp 签到已暂停", text=text)
                else:
                    self.post_message(title="⚠️ SakuraFrp 签到已暂停", text=text)
            except Exception as exc:
                logger.error(f"SakuraFrp每日签到：发送暂停通知失败：{exc}")

    def _save_history(self, results: List[Dict[str, Any]], now_str: str):
        history: List[Dict[str, Any]] = self.get_data(self._DATA_KEY) or []
        for res in results:
            history.append({
                "time": now_str,
                "account": res.get("account", ""),
                "success": bool(res.get("success")),
                "days": res.get("days", ""),
                "traffic": res.get("traffic", ""),
                "message": res.get("message", ""),
            })
        # 保留天数
        try:
            cutoff = datetime.now(self._TZ).timestamp() - self._history_days * 86400
            kept = []
            for rec in history:
                try:
                    ts = datetime.strptime(rec.get("time", ""), "%Y-%m-%d %H:%M:%S")
                    ts = ts.replace(tzinfo=self._TZ).timestamp()
                    if ts >= cutoff:
                        kept.append(rec)
                except Exception:
                    kept.append(rec)
            history = kept
        except Exception:
            pass
        # 最多 300 条
        history = history[-300:]
        self.save_data(self._DATA_KEY, history)

    def _notify(self, results: List[Dict[str, Any]]):
        if not self._notify_enabled or not results:
            return
        success = sum(1 for r in results if r.get("success"))
        total = len(results)
        lines = [f"共 {total} 个账号，成功 {success} 个" + ("" if success == total else "，存在失败")]
        for r in results:
            icon = "✅" if r.get("success") else "❌"
            extra = ""
            if r.get("days") not in ("", None):
                extra += f"，连续 {r.get('days')} 天"
            if r.get("traffic") not in ("", None):
                extra += f"，累计 {r.get('traffic')}"
            lines.append(f"{icon} {r.get('account')}：{r.get('message', '')}{extra}")
        title = "🌸 SakuraFrp 每日签到"
        text = "\n".join(lines)
        try:
            if NotificationType is not None:
                mtype = NotificationType.Plugin
                if self._notify_type:
                    try:
                        mtype = NotificationType[self._notify_type]
                    except (KeyError, TypeError):
                        mtype = NotificationType.Plugin
                self.post_message(mtype=mtype, title=title, text=text)
            else:
                self.post_message(title=title, text=text)
        except Exception as exc:
            logger.error(f"SakuraFrp每日签到：发送通知失败：{exc}")
