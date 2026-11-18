# SakuraFrp 每日签到（MoviePilot V3）

在 MoviePilot V3（`system_version >= 3.0.0`）中自动完成 [SakuraFrp（樱花内网穿透）](https://www.natfrp.com/) 的每日签到，领取签到流量。

## 功能

- 自动签到，领取每日签到流量
- 两种登录方式：
  - **账号密码**：自动完成 OpenID 登录 + GeeTest 校验
  - **网页 Cookie**：直接使用浏览器中的 SESSION Cookie（推荐，最稳定）
- 支持**多账号**（每行一个）
- GeeTest v3 协议握手（多数情况下无需识图自动放行），失败自动换 challenge 重试
- 定时任务（5 段 cron）、立即运行一次
- **随机错峰**：每日在随机时间执行；支持「每月重新随机」，每月换一个基准时段
- **签到流量统计图表**（累计流量趋势、累计签到天数趋势）
- **验证码失败保护**：验证码问题连续失败 2 次 → 当天停止签到，并发送 **Telegram** 通知
- 签到记录查看（最近 30 天 / 最多 100 条展示）
- 结果通知（复用 MoviePilot 通知渠道）
- 可选 HTTP(S) 代理

## 安装

### 方式一：本地插件目录（推荐用于自用/调试）

将本仓库的 `plugins.v3/sakurafrsignin` 目录整体复制到 MoviePilot V3 的插件目录下，重启 MoviePilot 后在「插件」页面即可看到 `SakuraFrp每日签到`。

> MoviePilot V3 的自定义插件通常位于 `config/plugins/`（镜像内 `/config/plugins`）。
> 具体路径以你的部署方式为准；本仓库同时提供了 `package.v3.json`，可作为插件仓库使用。

### 方式二：作为插件仓库

把整个仓库托管到 Git 服务（GitHub/Gitee 等），在 MoviePilot「设置 → 插件市场 → 添加插件仓库」中填入仓库地址即可安装。

安装后如提示缺少 `cryptography`，请执行：

```bash
pip install cryptography
```

## 配置说明

| 配置项 | 说明 |
| --- | --- |
| 启用插件 | 开启后才会注册定时任务 |
| 立即运行一次 | 保存配置后立刻执行一次签到（不影响定时任务） |
| 发送通知 | 签到完成后是否推送结果 |
| 通知类型 | 选择 MoviePilot 的通知渠道类型，默认「插件」 |
| 签到时间 | 5 段 cron 表达式，默认 `0 8 * * *`（每天 08:00，Asia/Shanghai） |
| 登录方式 | `账号密码` 或 `网页 Cookie` |
| 验证码重试次数 | GeeTest 命中点选验证码时换 challenge 重试的最大次数，默认 3 |
| 请求超时 | 单次 HTTP 请求超时秒数，默认 20 |
| 记录保留天数 | 签到记录保留天数，默认 30 |
| HTTP(S) 代理 | 可选，形如 `http://127.0.0.1:7890` |
| 启用随机错峰 | 开启后每日在「错峰窗口」内随机时间执行 |
| 错峰窗口（分钟） | 随机延迟上限，默认 60 |
| 每月重新随机 | 每个自然月重新抽取基准偏移，默认开启 |
| MoviePilot 通知 | 验证码连续失败暂停等事件通过 Telegram 推送 |
| Telegram Bot Token | 机器人 Token，例如 `123456:ABC-DEF...` |
| Telegram Chat ID | 接收消息的 chat id，例如 `-1001234567890` |
| 账号列表 | 每行一个账号，见下文格式 |

### 账号列表格式

**账号密码模式**（`登录方式=账号密码`）：

```
备注|用户名|密码
```

**Cookie 模式**（`登录方式=网页 Cookie`）：

```
备注|PHPSESSID=xxxxxxxxxxxxxxxx
```

或直接粘贴整段 Cookie：

```
备注|PHPSESSID=xxx; other=yyy
```

> **获取 Cookie**：浏览器登录 `https://www.natfrp.com/`，打开开发者工具（F12）→
> Application → Cookies，复制 `PHPSESSID` 的值（或整段 Cookie）。Cookie 会过期，失效后请更新。

## 工作原理

1. 使用 Cookie 或账号密码登录，建立带 SESSION 的会话；
2. 调用 `GET https://www.natfrp.com/cgi/v4/user/info` 读取 `sign` 字段判断今日是否已签到；
3. 若未签到：`GET /cgi/v4/user/sign?gt` 获取 GeeTest 参数 → 完成 GeeTest v3 协议握手拿到 `validate`；
4. `POST /cgi/v4/user/sign` 提交 `geetest_challenge / geetest_validate / geetest_seccode`；
5. 再次读取 `/user/info` 校验签到结果并记录、推送通知。

> 说明：SakuraFrp 的签到接口仅支持 SESSION 鉴权，访问密钥（OpenAPI Token）无法用于签到，
> 因此本插件使用 Cookie / 账号密码而非访问密钥。

## 随机错峰

- 开启「启用随机错峰」后，定时任务会在「签到时间」基础上叠加一个随机延迟（`0 ~ 错峰窗口` 分钟）后执行，避免固定在整点签到。
- 勾选「每月重新随机」时，每个自然月会重新抽取一个固定的基准偏移（保存在插件数据 `stagger_state`），每天再叠加 `0~5` 分钟的小抖动，实现「每月错峰、每天不同时刻」。
- 关闭「每月重新随机」时，每次执行都完全随机。
- 延迟在后台线程中等待，不阻塞 MoviePilot 调度器；若已有任务在执行，新触发会被跳过（防重复签到）。

## 签到流量统计图表

插件详情页（`get_page`）会展示：

- **签到累计流量趋势**（按天取当天最后一次签到后站点返回的累计签到流量）
- **累计签到天数趋势**
- 顶部概要（有记录天数 / 最近累计天数 / 当前累计流量）与最近签到记录表格

> 图表需要至少 2 天的记录才会显示。

## 验证码失败保护与 MoviePilot 通知

- **每一次 GeeTest 校验失败计 1 次错误**（按自然日 Asia/Shanghai 统计，跨天自动清零）。
- 同一日内累计失败达到 **2 次**，插件会**停止当天剩余的所有签到**（后续触发直接跳过），并推送 **Telegram** 告警。
- 插件会自动把「验证码重试次数」限制在当日剩余容错次数内，所以单次运行最多只会在第 2 次验证码失败后停止，不会无谓重试。
- Telegram 需在配置中填写 `Bot Token` 与 `Chat ID`；未配置时回退到 MoviePilot 通知渠道。
- 例：`验证码重试次数=3` 时，若第 1、2 轮都命中点选验证码，插件立即停止当天签到并告警，不再进行第 3 轮。

## 已知限制

- SakuraFrp 在签到前会进行 GeeTest 人机校验。本插件实现了「协议握手」流程，**大多数情况可直接通过**；
  若服务端持续返回「九宫格点选」验证码，该轮签到会失败；同一日累计 2 次验证码失败后插件会停止当天签到并 Telegram 告警，避免无效重试。
- Cookie 会过期，长期使用建议优先考虑账号密码模式（自动登录）。
- 请勿频繁触发签到，避免触发风控。

## 致谢

GeeTest v3 协议实现参考了以下 MIT 许可项目：

- [claaudy/sakurafrp-auto-sign](https://github.com/claaudy/sakurafrp-auto-sign)
- [zjwzhuzhu/frp-autosign](https://github.com/zjwzhuzhu/frp-autosign)

## 免责声明

本插件仅供学习与个人自动化使用，请遵守 SakuraFrp 的服务条款。因使用本插件造成的任何后果由使用者自行承担。
