# -*- coding: utf-8 -*-
"""
SakuraFrp 签到九宫格点选验证码识别（OpenAI 兼容视觉模型）。

参考实现（MIT）：https://github.com/zjwzhuzhu/frp-autosign (captcha_handler / auto_signin)
仅在插件内做精简：下载验证码图片 -> 多模态模型识别 -> 生成 GeeTest a 参数 -> verify。
"""

import base64
import json
import re
import time

import requests

try:
    from PIL import Image
except Exception:  # pragma: no cover - Pillow 缺失时退化为单图识别
    Image = None

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

NINE_PROMPT = (
    "这是极验(GeeTest)的九宫格点选验证码，一共两张图：\n"
    "第 1 张是完整验证码；第 2 张是底部那个【参考图标】的放大图（放大 3 倍，以它为准识别目标物品）。\n"
    "图片上方是 3 行 × 3 列的格子，每个格子里是一张物品的真实照片。\n"
    "任务：找出所有与参考图标属于同一种物品的格子。\n"
    "要点：\n"
    "1. 先仔细看清第 2 张放大图里到底是什么物品（不要被第 1 张里的大面积物体带偏）；\n"
    "2. 参考图标是线条简笔画，格子里的物品是真实照片，形状、角度、颜色、背景都可能不同；\n"
    "3. 只按「物品类别」判断，同一类物品的不同款式都算匹配；\n"
    "4. 不要选长得像但不同类的格子，也不要把参考图标本身当成格子；\n"
    "5. 匹配的格子可能有 1 到 5 个，必须全部找出。\n"
    "行号：从上到下为 1、2、3。列号：从左到右为 1、2、3。\n"
    "只输出JSON，不要任何解释，格式："
    '{"object":"目标物品名称","cells":[[行,列],[行,列]]}'
)

ICON_PROMPT = (
    '这是一个点选验证码。请识别图中需要点击的目标文字或图标，'
    '并返回每个目标的大致坐标位置。输出格式为JSON列表：'
    '[{"x": 100, "y": 200}, ...]。坐标原点在左上角。'
    '只输出JSON，不要其他文字。'
)


def _strip_json_fence(text: str) -> str:
    text = (text or "").strip()
    if text.startswith("```json") and text.endswith("```"):
        return text[7:-3].strip()
    if text.startswith("```") and text.endswith("```"):
        return text[3:-3].strip()
    return text


def _log(logger, level, msg):
    if not logger:
        return
    try:
        getattr(logger, level)(msg)
    except Exception:
        pass


def _vision_chat(images, prompt, cfg, logger=None, max_tokens=1200):
    base = (cfg.get("base_url") or "").rstrip("/")
    key = cfg.get("api_key") or ""
    model = cfg.get("model") or "gpt-4o"
    if not base or not key:
        _log(logger, "warning", "视觉模型未配置（缺少 base_url/api_key），无法识别点选验证码")
        return ""
    content = [{"type": "text", "text": prompt}]
    content += [{"type": "image_url", "image_url": {"url": u}} for u in images]
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": content}],
        "max_tokens": max_tokens,
        "stream": False,
    }
    proxies = cfg.get("proxies") or None
    for attempt in range(1, 3):
        try:
            resp = requests.post(
                f"{base}/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                timeout=180,
                verify=False,
                proxies=proxies,
            )
        except Exception as exc:
            _log(logger, "warning", f"视觉模型请求异常：{exc}")
            time.sleep(1)
            continue
        if resp.status_code != 200:
            _log(logger, "warning", f"视觉模型 HTTP {resp.status_code}: {resp.text[:200]}")
            return ""
        try:
            data = resp.json()
        except Exception:
            return ""
        choices = data.get("choices") or []
        if not choices:
            return ""
        message = choices[0].get("message") or {}
        out = message.get("content")
        if isinstance(out, str) and out.strip():
            return out.strip()
        if isinstance(out, list):
            parts = [p.get("text", "") for p in out if isinstance(p, dict) and p.get("type") == "text"]
            text = "\n".join(x for x in parts if x).strip()
            if text:
                return text
        if attempt < 2:
            time.sleep(1)
    return ""


def _parse_nine_cells(text: str):
    text = _strip_json_fence(text)
    raw_cells = []
    obj = None
    for cand in reversed(re.findall(r"\{[^{}]*\}", text)):
        try:
            parsed = json.loads(cand)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(parsed, dict) and ("cells" in parsed or "points" in parsed):
            obj = parsed
            break
    if isinstance(obj, dict):
        raw_cells = obj.get("cells") or obj.get("points") or []
    if not raw_cells:
        pairs = re.findall(r"\[\s*([1-3])\s*,\s*([1-3])\s*\]", text)
        if pairs:
            raw_cells = [[int(a), int(b)] for a, b in pairs]
        else:
            pairs = re.findall(r"([1-3])[_\-\s,]+([1-3])", text)
            if pairs:
                raw_cells = [[int(a), int(b)] for a, b in pairs]
    points = []
    for cell in raw_cells:
        row = col = None
        if isinstance(cell, (list, tuple)) and len(cell) >= 2:
            row, col = int(cell[0]), int(cell[1])
        elif isinstance(cell, str):
            nums = re.findall(r"[1-3]", cell)
            if len(nums) >= 2:
                row, col = int(nums[0]), int(nums[1])
        if row is None or not (1 <= row <= 3 and 1 <= col <= 3):
            continue
        point = f"{col}_{row}"
        if point not in points:
            points.append(point)
    if obj and isinstance(obj, dict) and obj.get("object"):
        _log(None, "info", "")
    return points


def _icon_zoom_png(img_bytes: bytes, scale: int = 3):
    if Image is None:
        return None
    from io import BytesIO

    im = Image.open(BytesIO(img_bytes)).convert("RGB")
    w, h = im.size
    grid_h = int(h * 0.83)
    icon = im.crop((0, grid_h, w // 3, h))
    icon = icon.resize((icon.width * scale, icon.height * scale), Image.LANCZOS)
    out = BytesIO()
    icon.save(out, format="PNG")
    return out.getvalue()


def recognize_captcha(image_url: str, pic_type: str, cfg, logger=None) -> list:
    proxies = cfg.get("proxies") or None
    try:
        resp = requests.get(
            image_url,
            timeout=30,
            headers={"User-Agent": _UA, "Referer": "https://www.natfrp.com/"},
            verify=False,
            proxies=proxies,
        )
        img_bytes = resp.content
    except Exception as exc:
        _log(logger, "warning", f"验证码图片下载失败：{exc}")
        return []
    full = "data:image/jpeg;base64," + base64.b64encode(img_bytes).decode()

    if pic_type == "nine":
        images = [full]
        zoom = _icon_zoom_png(img_bytes)
        if zoom:
            images.append("data:image/png;base64," + base64.b64encode(zoom).decode())
        for attempt in range(1, 3):
            text = _vision_chat(images, NINE_PROMPT, cfg, logger)
            if not text:
                continue
            _log(logger, "info", f"视觉模型输出：{text[:300]}")
            points = _parse_nine_cells(text)
            if points:
                return points
        return []

    text = _vision_chat([full], ICON_PROMPT, cfg, logger)
    if not text:
        return []
    try:
        coords = json.loads(_strip_json_fence(text))
        if isinstance(coords, dict):
            coords = coords.get("coordinates", coords.get("points", []))
        points = []
        for c in coords:
            if isinstance(c, dict):
                if "x" in c and "y" in c:
                    points.append(f"{c['x']}_{c['y']}")
                elif "point_2d" in c:
                    pt = c["point_2d"]
                    points.append(f"{pt[0]}_{pt[1]}")
        return points
    except (json.JSONDecodeError, KeyError, TypeError, IndexError):
        return []


def solve_click_captcha(crack, cfg, logger=None) -> str:
    """对点击型验证码：取图 -> 识别 -> verify，返回 validate 或 None。"""
    max_retries = int(cfg.get("max_retries") or 3)
    for attempt in range(1, max_retries + 1):
        try:
            pic_type, pic_url = crack.get_pic(0 if attempt == 1 else attempt)
        except Exception as exc:
            _log(logger, "warning", f"获取点选验证码图片失败：{exc}")
            continue
        _log(logger, "info", f"点选验证码类型={pic_type}，开始视觉识别（第 {attempt} 次）")
        points = recognize_captcha(pic_url, pic_type, cfg, logger)
        if not points:
            _log(logger, "warning", "视觉识别未得到点击位置，重试")
            continue
        _log(logger, "info", f"识别点击位置：{points}")
        try:
            result = crack.verify(points)
        except Exception as exc:
            _log(logger, "warning", f"提交点选结果异常：{exc}")
            continue
        if result.get("status") == "success" and (result.get("data") or {}).get("result") == "success":
            return (result.get("data") or {}).get("validate")
        _log(logger, "warning", f"点选验证未通过：{str(result)[:200]}")
    return None
