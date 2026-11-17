"""
SakuraFrp（樱花内网穿透）每日签到 —— MoviePilot V3 插件

功能
----
- 自动完成 SakuraFrp（https://www.natfrp.com）每日签到，领取签到流量
- 支持「账号密码」自动登录（OpenID + GeeTest）或「网页 Cookie」免登录两种方式
- 支持多账号、失败重试、签到记录、结果通知
- 随机错峰：每日在随机时间执行，支持「每月重新随机」避免固定时刻
- 签到流量统计图表（累计流量趋势、累计签到天数趋势）
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


def _mp_setting(name: str, default: str = "") -> str:
    """从 MoviePilot 运行时配置读取默认值（视觉模型复用系统 LLM 配置）。"""
    try:
        from app.sdk.config import settings  # type: ignore
        value = getattr(settings, name, None)
        if value:
            return str(value)
    except Exception:
        pass
    try:
        from app.core.config import settings  # type: ignore
        value = getattr(settings, name, None)
        if value:
            return str(value)
    except Exception:
        pass
    try:
        import os
        return os.environ.get(name, default)
    except Exception:
        return default


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
    plugin_version = "1.1.7"
    plugin_author = "RDevils7"
    author_url = "https://github.com/RDevils7"
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
    # 视觉模型（用于九宫格点选验证码）
    _vision_base_url: str = ""
    _vision_api_key: str = ""
    _vision_model: str = ""
    _backfill_gain: str = ""

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
        # 视觉模型（九宫格点选验证码）；留空则复用 MoviePilot 的 LLM 配置
        self._vision_base_url = (config.get("vision_base_url") or "").strip() or _mp_setting("LLM_BASE_URL")
        self._vision_api_key = (config.get("vision_api_key") or "").strip() or _mp_setting("LLM_API_KEY")
        self._vision_model = (config.get("vision_model") or "").strip() or _mp_setting("LLM_MODEL", "gpt-4o")
        # 一次性维护项：把指定流量（GB）补录到最近一条缺少 gain 的成功记录
        self._backfill_gain = str(config.get("backfill_gain") or "").strip()
        if not getattr(self, "_lock", None):
            self._lock = threading.Lock()
        self._apply_gain_backfill()

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
            "vision_base_url": self._vision_base_url,
            "vision_api_key": self._vision_api_key,
            "vision_model": self._vision_model,
            "backfill_gain": self._backfill_gain,
        })

    def _apply_gain_backfill(self):
        raw = (self._backfill_gain or "").strip()
        if not raw:
            return
        try:
            value = float(raw)
        except (TypeError, ValueError):
            self._backfill_gain = ""
            return
        history = self.get_data(self._DATA_KEY) or []
        for rec in reversed(history):
            if rec.get("success") and rec.get("gain") in (None, ""):
                rec["gain"] = value
                self.save_data(self._DATA_KEY, history)
                logger.info(f"SakuraFrp每日签到：已补录最近一次签到获得流量 {value} GB")
                break
        self._backfill_gain = ""
        try:
            self._save_config()
        except Exception:
            pass

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
                        "content": [
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{
                                    "component": "VTextField",
                                    "props": {
                                        "model": "vision_base_url",
                                        "label": "视觉模型 Base URL（识别点选验证码，可留空用系统 LLM）",
                                        "placeholder": "https://api.openai.com/v1",
                                    },
                                }],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{
                                    "component": "VTextField",
                                    "props": {
                                        "model": "vision_api_key",
                                        "label": "视觉模型 API Key（可留空用系统 LLM）",
                                        "type": "password",
                                    },
                                }],
                            },
                            {
                                "component": "VCol",
                                "props": {"cols": 12, "md": 4},
                                "content": [{
                                    "component": "VTextField",
                                    "props": {
                                        "model": "vision_model",
                                        "label": "视觉模型名称（可留空用系统 LLM）",
                                        "placeholder": "gpt-4o",
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
            "vision_base_url": "",
            "vision_api_key": "",
            "vision_model": "",
            "accounts": "",
        }

    @staticmethod
    def _fill_gains(history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """为历史记录补全「本次获得流量」：优先用记录里的 gain，缺失则用累计流量差值推算。"""
        last_traffic: Dict[str, float] = {}
        filled: List[Dict[str, Any]] = []
        for rec in history:
            item = dict(rec)
            try:
                traffic_value = float(item.get("traffic"))
            except (TypeError, ValueError):
                traffic_value = None
            gain_value = item.get("gain")
            try:
                gain_value = float(gain_value) if gain_value not in (None, "") else None
            except (TypeError, ValueError):
                gain_value = None
            if gain_value is None:
                previous = last_traffic.get(item.get("account"))
                if traffic_value is not None and previous is not None and traffic_value >= previous:
                    gain_value = round(traffic_value - previous, 2)
            item["gain"] = gain_value
            if traffic_value is not None:
                last_traffic[item.get("account")] = traffic_value
            filled.append(item)
        return filled

    @staticmethod
    def _fmt_gain(gain) -> str:
        if gain in (None, ""):
            return "—"
        try:
            value = float(gain)
        except (TypeError, ValueError):
            return "—"
        if value == 0:
            return "0 GB"
        text = f"{value:.2f}".rstrip("0").rstrip(".")
        return f"+{text} GB"

    @staticmethod
    def _fmt_traffic(traffic) -> str:
        if traffic in (None, ""):
            return "—"
        try:
            value = float(traffic)
        except (TypeError, ValueError):
            return str(traffic)
        text = f"{value:.2f}".rstrip("0").rstrip(".")
        return f"{text} GB"

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

        records = self._fill_gains(history)
        today = datetime.now(self._TZ).strftime("%Y-%m-%d")
        today_records = [r for r in records if (r.get("time") or "")[:10] == today]

        latest_by_account: Dict[str, Dict[str, Any]] = {}
        for rec in records:
            latest_by_account[rec.get("account", "")] = rec

        last = records[-1] if records else {}
        last_gain = last.get("gain")
        last_days = last.get("days", "")
        cum_traffic = last.get("traffic", "")
        for rec in reversed(records):
            if rec.get("traffic") not in (None, ""):
                cum_traffic = rec.get("traffic")
                break

        today_ok = sum(1 for r in today_records if r.get("success"))
        today_fail = sum(1 for r in today_records if not r.get("success"))
        today_gain = 0.0
        gain_by_account_today: Dict[str, float] = {}
        for r in today_records:
            if r.get("success") and r.get("gain") is not None:
                value = float(r.get("gain") or 0)
                today_gain += value
                account = r.get("account", "")
                gain_by_account_today[account] = gain_by_account_today.get(account, 0.0) + value

        css = """
            .sfp-page { display: flex; flex-direction: column; gap: 12px; }
            .sfp-summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; }
            .sfp-stat { min-width: 0; padding: 10px 12px; border: 1px solid rgba(var(--v-theme-on-surface), .08); border-radius: 8px; }
            .sfp-stat__head { display: flex; align-items: center; gap: 6px; min-width: 0; color: rgba(var(--v-theme-on-surface), .7); font-size: .75rem; font-weight: 600; line-height: 1.25; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
            .sfp-stat__value { margin-top: 8px; font-size: 1.25rem; font-weight: 700; line-height: 1.1; }
            .sfp-stat__meta { margin-top: 4px; color: rgba(var(--v-theme-on-surface), .56); font-size: .72rem; line-height: 1.25; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
            .sfp-section { min-width: 0; }
            .sfp-section-head { display: flex; align-items: center; gap: 8px; min-height: 30px; margin-bottom: 6px; }
            .sfp-section-title { font-size: .95rem; font-weight: 700; letter-spacing: 0; }
            .sfp-table-wrap { overflow-x: auto; border: 1px solid rgba(var(--v-theme-on-surface), .08); border-radius: 8px; }
            .sfp-table { min-width: 620px; }
            .sfp-table table { width: 100%; border-collapse: collapse; }
            .sfp-table th, .sfp-table td { padding: 7px 10px; text-align: left; white-space: nowrap; font-size: .85rem; }
            .sfp-table th { font-weight: 600; color: rgba(var(--v-theme-on-surface), .7); }
            .sfp-table tbody tr + tr td { border-top: 1px solid rgba(var(--v-theme-on-surface), .06); }
        """

        def stat_card(title: str, value: str, meta: str, color: str, icon: str) -> dict:
            return {
                "component": "div",
                "props": {"class": "sfp-stat"},
                "content": [
                    {
                        "component": "div",
                        "props": {"class": "sfp-stat__head"},
                        "content": [
                            {"component": "VIcon", "props": {"size": "x-small", "color": color}, "text": icon},
                            {"component": "span", "text": title},
                        ],
                    },
                    {"component": "div", "props": {"class": f"sfp-stat__value text-{color}"}, "text": value},
                    {"component": "div", "props": {"class": "sfp-stat__meta"}, "text": meta},
                ],
            }

        def make_table(headers: List[str], rows: List[List[str]]) -> dict:
            head_cells = [{"component": "th", "text": h} for h in headers]
            body_rows = []
            for row in rows:
                body_rows.append({
                    "component": "tr",
                    "content": [{"component": "td", "text": str(cell)} for cell in row],
                })
            return {
                "component": "div",
                "props": {"class": "sfp-table-wrap"},
                "content": [{
                    "component": "VTable",
                    "props": {"hover": True, "density": "compact", "class": "sfp-table"},
                    "content": [
                        {"component": "thead", "content": [{"component": "tr", "content": head_cells}]},
                        {"component": "tbody", "content": body_rows},
                    ],
                }],
            }

        def section(title: str, chip: str, table: dict, icon: str) -> dict:
            return {
                "component": "div",
                "props": {"class": "sfp-section"},
                "content": [
                    {
                        "component": "div",
                        "props": {"class": "sfp-section-head"},
                        "content": [
                            {"component": "VIcon", "props": {"size": "small", "color": "primary"}, "text": icon},
                            {"component": "span", "props": {"class": "sfp-section-title"}, "text": title},
                            {"component": "VSpacer"},
                            {"component": "VChip", "props": {"size": "x-small", "variant": "tonal", "color": "primary"}, "text": chip},
                        ],
                    },
                    table,
                ],
            }

        total_accounts = max(len(today_records), len(latest_by_account))
        cards = [
            stat_card("今日签到", f"{today_ok}/{total_accounts}", f"失败 {today_fail} 个",
                      "success" if not today_fail else "warning", "mdi-calendar-check"),
            stat_card("今日签到获得流量", self._fmt_gain(today_gain) if today_gain else "0 GB",
                      f"最近一次 {self._fmt_gain(last_gain)}", "primary", "mdi-swap-vertical-bold"),
            stat_card("累计签到天数", f"{last_days if last_days not in (None, '') else '—'} 天",
                      "最近一次记录", "info", "mdi-fire"),
            stat_card("累计签到流量", self._fmt_traffic(cum_traffic), "签到累计", "deep-purple", "mdi-chart-areaspline"),
        ]

        account_rows = []
        for account, rec in sorted(latest_by_account.items(),
                                   key=lambda kv: kv[1].get("time", ""), reverse=True):
            account_rows.append([
                account,
                "✅ 成功" if rec.get("success") else "❌ 失败",
                self._fmt_gain(gain_by_account_today.get(account)) if account in gain_by_account_today else "—",
                str(rec.get("days", "")),
                self._fmt_traffic(rec.get("traffic")),
                rec.get("time", ""),
            ])

        detail_rows = []
        for rec in reversed(records[-100:]):
            detail_rows.append([
                rec.get("time", ""),
                rec.get("account", ""),
                "✅ 成功" if rec.get("success") else "❌ 失败",
                self._fmt_gain(rec.get("gain")),
                str(rec.get("days", "")),
                self._fmt_traffic(rec.get("traffic")),
                rec.get("message", ""),
            ])

        page: List[dict] = [{"component": "style", "text": css}]
        page.append({
            "component": "div",
            "props": {"class": "sfp-page"},
            "content": [
                {"component": "div", "props": {"class": "sfp-summary"}, "content": cards},
                section("账号概览", f"{len(latest_by_account)} 个账号",
                        make_table(["账号", "今日状态", "今日获得流量", "累计天数", "累计流量", "最近时间"], account_rows),
                        "mdi-account-check"),
                section("最近记录", f"{len(records)} 条",
                        make_table(["时间", "账号", "结果", "本次获得", "累计天数", "累计流量", "说明"], detail_rows),
                        "mdi-history"),
            ],
        })

        charts = self._build_charts(records)
        if charts:
            page.append({"component": "VRow", "content": charts})
        return page

    def _build_charts(self, history: List[Dict[str, Any]]) -> List[dict]:
        """根据历史记录构建「签到流量」「累计天数」折线图。"""
        traffic_by_date: Dict[str, float] = {}
        days_by_date: Dict[str, int] = {}
        gain_by_date: Dict[str, float] = {}
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
            if rec.get("gain") is not None:
                try:
                    gain_by_date[d] = gain_by_date.get(d, 0.0) + float(rec.get("gain"))
                except (TypeError, ValueError):
                    pass

        dates = sorted(set(list(traffic_by_date.keys()) + list(days_by_date.keys()) + list(gain_by_date.keys())))
        if len(dates) < 2:
            return []
        traffic_series = [traffic_by_date.get(d) for d in dates]
        days_series = [days_by_date.get(d) for d in dates]
        gain_series = [round(gain_by_date.get(d, 0.0), 2) for d in dates]

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
                "累计签到天数趋势",
                [{"name": "累计签到天数", "data": days_series}], "天",
            ))
        if any(gain_series):
            charts.append(line_chart(
                "每日签到获得流量（GB）",
                [{"name": "每日获得流量", "data": gain_series}], "GB",
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
        proxies = {"http": self._proxy, "https": self._proxy} if self._proxy else None
        vision = {
            "base_url": self._vision_base_url,
            "api_key": self._vision_api_key,
            "model": self._vision_model,
            "proxies": proxies,
            "max_retries": 3,
        }
        return GeeTestSolver(
            gt=gt, challenge=challenge, referer=referer, logger=logger,
            timeout=self._timeout, vision=vision,
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
                    "gain": 0.0,
                    "message": f"今日已签到（累计 {sign.get('days', '?')} 天）",
                    "days": sign.get("days", ""),
                    "traffic": sign.get("traffic", ""),
                    "user": name,
                }
            result = client.do_sign(self._solver_factory, retries=rounds)
            extra = result.get("extra") or {}
            before_traffic = sign.get("traffic")
            after_traffic = extra.get("traffic", before_traffic)
            gain = None
            try:
                if before_traffic is not None and after_traffic is not None:
                    gain = round(float(after_traffic) - float(before_traffic), 2)
            except (TypeError, ValueError):
                gain = None
            return {
                "success": bool(result.get("success")),
                "captcha_error": bool(result.get("captcha_error")),
                "captcha_failures": int(result.get("captcha_failures") or 0),
                "gain": gain,
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
                "gain": res.get("gain"),
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
        total_gain = sum(float(r.get("gain") or 0) for r in results if r.get("success"))
        head = f"共 {total} 个账号，成功 {success} 个" + ("" if success == total else "，存在失败")
        if total_gain:
            head += f"，本次共获得 {self._fmt_gain(total_gain)}"
        lines = [head]
        for r in results:
            icon = "✅" if r.get("success") else "❌"
            extra = ""
            if r.get("success") and r.get("gain") is not None:
                extra += f"，本次获得 {self._fmt_gain(r.get('gain'))}"
            if r.get("days") not in ("", None):
                extra += f"，累计 {r.get('days')} 天"
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
