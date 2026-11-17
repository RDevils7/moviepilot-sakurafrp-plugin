# MoviePilot 插件仓库 · SakuraFrp 每日签到

本仓库提供 MoviePilot 插件：**SakuraFrp 每日签到**（可同时支持 V2 / V3）。

| 插件 | 适用版本 | 目录 |
| --- | --- | --- |
| SakuraFrp每日签到 | MoviePilot V2 | `plugins.v2/sakurafrsignin/` |
| SakuraFrp每日签到 | MoviePilot V3 | `plugins.v3/sakurafrsignin/` |

插件清单：V2 为 `package.v2.json`，V3 为 `package.v3.json`。

## 安装

### MoviePilot V3（`system_version >= 3.0.0`）

- 方式一（插件仓库）：把整个仓库托管到 Git 服务后，在 MoviePilot「设置 → 插件市场/插件仓库 → 添加仓库」填入地址，安装「SakuraFrp每日签到」。
- 方式二（手动）：把 `plugins.v3/sakurafrsignin` 整个目录复制到 MoviePilot V3 的插件目录（一般为 `config/plugins/`），并 `pip install cryptography`，重启后启用。

### MoviePilot V2

- 把 `plugins.v2/sakurafrsignin` 复制到 V2 插件目录，或作为插件仓库安装。

详见 [插件说明](plugins.v3/sakurafrsignin/README.md)（V2 说明见 `plugins.v2/sakurafrsignin/README.md`，内容基本一致）。

## 功能概览

- 自动签到（账号密码 / 网页 Cookie，多账号）
- 随机错峰（支持每月重新随机）
- 签到流量统计图表（累计流量 / 累计天数趋势）
- 验证码连续失败 2 次 → 当天停止签到 + Telegram 通知
- 定时任务、立即运行一次、结果通知
