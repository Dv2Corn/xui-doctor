[English](README.md) | [Русский](README.ru.md) | [فارسی](README.fa.md) | **[简体中文](README.zh.md)**

# xui-doctor

一个小巧的只读工具，用于检查 [3x-ui](https://github.com/MHSanaei/3x-ui)
面板及其分支 [still-ui](https://github.com/Dv2Corn/still-ui) 的运行状况和配置。

它登录面板 API，读取服务器状态、入站（inbound）、主机（host）和设置，按严重程度
分组列出已损坏或有风险的地方，并为每一项给出一行修复建议。它不会修改面板上的
任何内容。

在一个临时测试面板上的输出（过长的行用 "..." 省略）：

```
$ XUI_API_TOKEN=... xui-doctor check --url http://127.0.0.1:12053/doctor-test/
xui-doctor v0.1.0: http://127.0.0.1:12053/***/
panel: 3x-ui 3.11.0, Xray 26.10.21, auth: API token

== CRITICAL ==
- [xray] host "edge-host" -> inbound #1 "reality-ios" (vless, port 24443): ... share links here
  use fp=edge, which has none, so clients using them cannot connect
- [xray] inbound #1 "reality-ios" (vless, port 24443): Xray 26.10.21 (>= 26.9.8) refuses REALITY
  ClientHellos without an X25519MLKEM768 key share; share links here use fp=ios, which has none,
  so clients using them cannot connect
  fix: Set the uTLS fingerprint to chrome, firefox or safari and let clients refresh the
  subscription, or pin Xray 26.6.27 in the panel's Xray version switcher ...
- [xray] host "edge-host" -> inbound #1 "reality-ios" (vless, port 24443): ... this host has
  "Mihomo X25519" on, so its Clash subscription turns ML-KEM off and mihomo clients are refused
- [tls] inbound #4 "trojan-tls-inline" (trojan, port 24445) inline certificate: certificate
  expired on 2026-11-01 23:25 UTC
  fix: Replace the inline certificate with a renewed one.

== WARN ==
- [xray] REALITY clients: ... sing-box based clients (sing-box, Hiddify, Karing, NekoBox; tested
  1.12.12 and 1.14.4) cannot connect with any fingerprint; ...
- [clients] clients: 1 client has an IP limit (limitIp) but fail2ban is not usable on the panel
  host (enabled=no, installed=no, usable=no), so the limit is not enforced
- [security] login: two-factor authentication is off
  fix: Enable it in Settings -> Authentication -> Two-factor authentication.

== INFO ==
- [tls] TLS inbounds: 1 certificate file not checked; run with --local on the panel host to read them

summary: 4 critical, 3 warn, 1 info, 3 ok
(OK lines hidden; use --verbose to show them)
```

## 支持的面板

| 面板 | 测试版本 | 说明 |
|---|---|---|
| 3x-ui (MHSanaei) | v3.11.0（Docker 镜像 `ghcr.io/mhsanaei/3x-ui:v3.11.0`） | v3.x API；更早的 2.x 面板可能部分可用（未测试） |
| still-ui (Dv2Corn) | v1.3.0（发布包） | 通过服务器状态中的 `upstreamVersion` 字段识别 |

工具会报告它识别到的面板类型。版本检查时，3x-ui 与 `MHSanaei/3x-ui` 的最新发布
比较，still-ui 与 `Dv2Corn/still-ui` 的最新发布比较。

## 安装

```
go install github.com/Dv2Corn/xui-doctor/cmd/xui-doctor@latest
```

或者构建静态二进制文件（不使用 CGO，只依赖标准库）：

```
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o xui-doctor ./cmd/xui-doctor
```

## 用法

```
xui-doctor check --url https://HOST:PORT/BASEPATH/ [--insecure] [--json] [--local]
                 [--dial-targets] [--offline] [--verbose] [--timeout 20s] [--lang en|ru]
```

凭据只从环境变量读取，因此不会留在 shell 历史或进程列表中：

| 变量 | 含义 |
|---|---|
| `XUI_API_TOKEN` | API 令牌（Settings -> Authentication -> API tokens）。*Administrator* 令牌可以读取全部内容；*Monitoring* 令牌只能做 Xray 和版本检查。 |
| `XUI_USERNAME`、`XUI_PASSWORD` | 面板登录用户名和密码，未设置令牌时使用 |
| `XUI_2FA_CODE` | 当前的两步验证码（如果启用了 2FA） |
| `XUI_URL` | `--url` 的默认值 |

| 参数 | 含义 |
|---|---|
| `--url` | 面板地址，包含其 URI 路径（base path）；拒绝包含用户名和密码的地址 |
| `--insecure` | 接受自签名或域名不匹配的面板证书 |
| `--json` | 机器可读的输出 |
| `--local` | 工具运行在面板所在主机上：额外读取证书文件和监听中的套接字（`/proc/net`），并从这里探测 REALITY 目标（包括本地和私有地址的目标） |
| `--dial-targets` | 从工具运行的机器上探测 REALITY 目标（报告中会注明：这里不一定是面板主机）；解析到 loopback、私有、link-local、CGNAT、文档用途、NAT64/6to4 或其他 IANA 特殊用途地址的目标会被跳过 |
| `--offline` | 不向 GitHub 查询最新发布 |
| `--verbose` | 同时输出 OK 行 |
| `--lang` | 输出语言，`en` 或 `ru`；不指定时，俄语 locale（`LC_ALL`、`LC_MESSAGES` 或 `LANG` 以 `ru` 开头，按此顺序检查）会选择俄语，其余情况为英语 |

退出码：`0` 没有比 INFO 更严重的问题，`1` 有警告，`2` 有严重问题，`3` 检查
无法运行（地址错误、登录被拒绝等）。

### 输出语言

文本输出目前只有英语和俄语，暂时没有中文。默认是英语。`--lang ru` 切换为俄语；
不加该参数时，由 `LC_ALL`、`LC_MESSAGES`、`LANG` 中第一个非空的变量决定：以 `ru`
开头（例如 `ru_RU.UTF-8`）则输出俄语，其他任何值（包括 `zh_CN.UTF-8`）都输出
英语。无论 locale 是什么，`--lang en` 都会输出英语。

`--json` 输出始终是英语，并且每条结果都带有一个固定的消息 `id`，这样脚本不依赖
具体措辞或 locale。

### 它发送哪些请求

只有以下请求（相对于面板地址）：

- `GET /csrf-token`、`POST /login`、`POST /logout` - 工具自己的会话（使用令牌时不需要）；
- `GET /panel/api/server/status`、`GET /panel/api/inbounds/list`、
  `GET /panel/api/hosts/list`、`GET /panel/api/server/fail2banStatus`；
- `POST /panel/api/setting/all` - 这是读取操作；面板以 POST 方式路由它，并在响应中
  清空机密值（机器人令牌、2FA 密钥）。

使用 `--local` 或 `--dial-targets` 时，它还会与 REALITY 目标进行 TLS 握手：每个
域名只解析一次，然后连接经过检查的地址（超时 5 秒，每次运行最多 20 次握手；跳过的
会列出）。不使用 `--local` 时，绝不会连接非公网的目标地址；拨号器还会再次检查实际
连接的地址。

另外，除非使用 `--offline`，还会向 `api.github.com/repos/<repo>/releases/latest`
发送一次匿名请求。客户端的 UUID、密码以及 REALITY 私钥只会读入内存用于相互比较，
永远不会打印出来。

## 检查项

| ID | 检查内容 |
|---|---|
| `xray` | Xray 的状态和版本与下文 REALITY 变化的对照；REALITY 入站和订阅主机的 uTLS 指纹；主机的 "Mihomo X25519" 开关 |
| `reality` | target、serverNames、privateKey、minClientVer、shortIds，完全按照 Xray-core 的校验方式；链接用的公钥为空；`show`；使用 `--local`/`--dial-targets` 时：目标对每个 serverName 是否支持 TLS 1.3、h2 并提供有效证书 |
| `tls` | TLS 入站内联证书以及面板所出示证书的有效期；使用 `--local` 时还检查入站、面板和订阅服务器的证书文件（已过期：CRITICAL，少于 7 天：WARN） |
| `ports` | 已启用的入站（以及面板 / 订阅服务器）是否会在同一地址上占用同一端口和传输协议，规则与面板自身的 TCP/UDP 规则一致；使用 `--local` 时还检查已启用但无人监听的入站 |
| `clients` | 已过期或流量用尽但仍处于启用状态的客户端；同一入站内共用一个 UUID/密码的两个客户端；fail2ban 不可用时设置的 IP 限制 |
| `security` | admin/admin（仅当你用它运行工具时）、明文 HTTP、URI 路径为 `/`、默认端口 2053 和默认订阅路径、未启用 2FA、存在 Telegram 机器人令牌 |
| `version` | 面板版本与 GitHub 最新发布的对比 |

运行在远程节点上的入站会被依赖本地 Xray 的检查跳过；请对每个节点单独运行本工具。

### 考虑过但放弃的检查

- *同一邮箱用于多个入站* - 从 3x-ui 3.x 起，客户端是一条记录，可以有意关联到多个
  入站。
- *spiderX 格式* - 面板会为每个客户端生成以 `/` 开头的 `spx`。
- *在本地读取 Xray 二进制文件的版本* - 状态 API 已经报告了正在运行的内核版本。
- *猜测默认凭据* - 工具从不尝试密码；只有当你用 admin/admin 运行它时才会标记。

## 为什么需要 Xray 检查

官方 Xray-core 的 REALITY 服务端有两处变化，会让之前能用的客户端失效，而面板对此
没有任何提示：

1. **26.7.11 - 26.7.28：** REALITY 服务端的 `minClientVer` 默认值为 26.3.27
   （[Xray-core af7eb680](https://github.com/XTLS/Xray-core/commit/af7eb68028732a8ee3c0e5d6ab2b8a657bb2e770)）。
   不发送 Xray 版本的客户端（sing-box、mihomo）以及低于 26.3.27 的 Xray 客户端
   都会被拒绝，除非入站显式设置了 `minClientVer`。
2. **26.9.8 及以后：** 服务端拒绝在可选的 X25519 之前不带 X25519MLKEM768 密钥
   共享的任何 ClientHello
   （[XTLS/REALITY 8cdf7bf9](https://github.com/XTLS/REALITY/commit/8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8)，
   由
   [47cfe999](https://github.com/XTLS/Xray-core/commit/47cfe9994a6b39b1f673ba35e62b091bcce15a71) 引入 Xray-core，首次出现在
   v26.9.8；该标签已在上游删除，v26.9.9 是第一个公开发布的版本）。同一版本又把
   `minClientVer` 的默认值注释掉了。被拒绝的 hello 会被当作非 REALITY 访客转发给
   目标，因此客户端看到的是目标的真实证书。

测试矩阵（官方二进制文件，全部在 loopback 上，目标 `www.nvidia.com`，每格 4 次
请求；脚本见 [`tools/reality-matrix`](tools/reality-matrix)）：

| 服务端 | Xray 客户端 chrome / firefox / safari | Xray 客户端 ios / edge / qq | sing-box 1.12.12 和 1.14.4，任意 fp | mihomo 1.19.33 | mihomo + `support-x25519mlkem768: true`，chrome |
|---|---|---|---|---|---|
| 26.6.27 | ok | ok | ok | ok | ok |
| 26.7.28 | ok | ok | 拒绝 | 拒绝 | 拒绝 |
| 26.9.9 | ok | **拒绝** | **拒绝** | **拒绝** | ok |
| 26.10.31 | ok | **拒绝** | **拒绝** | **拒绝** | ok |

Xray 客户端 26.6.27 和 26.10.31 表现相同。在此环境中，`android` 和 `360` 对所有
服务端都失败；`random`/`randomized*` 每个连接选择不同的 hello，只是有时能用。经过
面板的端到端测试结果相同：在 3x-ui 3.11.0（自带 Xray 26.10.21）和 still-ui 1.3.0
（Xray 26.10.31）上，`fp=ios` 的入站对 fp 为 ios 的 Xray 客户端为 0/3，对 chrome
和 safari 为 3/3，对 sing-box 1.14.4 为 0/3。

怎么办，正如检查结果所说：把链接的指纹改为 chrome、firefox 或 safari，或者在面板
的 Xray 版本切换中固定使用 Xray 26.6.27。带 ML-KEM 的 hello 更大 - 用 Xray
26.10.31 实测：chrome 1820、firefox 1889、safari 1537 字节，而 ios/edge/qq 为
517 字节 - 需要两个 TCP 分段，部分移动网络处理不好。面板自带的 Clash 订阅已经为
mihomo 客户端设置了 `support-x25519mlkem768: true`；开启了 "Mihomo X25519" 的
主机会把它关掉。

打过补丁、仍接受旧 hello 的内核会报告相同的版本号；工具无法区分，因此阅读 `xray`
检查结果时请记住这一点。

## 开发

```
go vet ./...
go test ./...
```

消息位于 `internal/i18n/catalog.go`，包含英语和俄语。如果某条消息缺少俄语文本、
两种文本使用的格式动词（`%s`、`%d` 等）不一致，或者代码使用了目录中不存在的 ID，
测试就会失败。

`testdata/` 中保存的是从临时 3x-ui 3.11.0 和 still-ui 1.3.0 面板录制的响应，其中
的 UUID、密钥、密码和 GUID 已替换为假值。`internal/doctor` 通过一个伪造的面板回放
这些响应，该面板执行相同的 CSRF 和会话规则，任何超出上述只读范围的请求都会让测试
失败。

## 许可证

MIT。与 3x-ui 和 Xray-core 项目无关。
