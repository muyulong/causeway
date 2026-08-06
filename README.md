# Causeway — 自用 SSH 管理平台

在"目标机只能经堡垒机访问、且禁止用自有用户名直接 SSH 登录"的环境里，
让本地电脑用**标准 SSH 工具**直接连上目标机，并提供一个 Web 控制台。

装好 Agent 之后，堡垒机、deploy、su 这套流程与日常操作彻底无关。

## 能做什么

- `ssh` / `scp` / `sftp` / `rsync` / VS Code Remote / `git+ssh` / `sshfs` 全部直接可用
- Web 控制台：在线状态、Web 终端、审计日志、停用/启用、手动重连
- **Agent 在线升级**：Web 里点一下，把新版本推送到指定目标机并自动重启
- 反向 SOCKS：让目标机按需借用工作站的网络（Web 开关控制，默认关）
- Agent 自动重连、systemd user 保活
- **多人使用**：用户名+密码登录（管理员/成员）、按人审计、
  服务器默认用户（Agent 用 sudo 切换到目标机上的真实账户）、
  用户公钥集中管理并自动下发到所有 Agent

## 架构

```mermaid
flowchart LR
  L[本地电脑 ssh/scp/rsync/VS Code] -- SSH 22001/22002... --> W[工作站<br>中继 + Web 控制台 + SOCKS 网关]
  B[浏览器] -- HTTPS --> W
  W <-- TLS 反向隧道 --> A1[Agent·私人sshd@服务器1]
  W <-- TLS 反向隧道 --> A2[Agent·私人sshd@服务器2]
```

- **agent**（Go 单文件，目标机上以你的用户运行）：内置 SSH 服务器
  （公钥认证读目标机 `~/.ssh/authorized_keys`、PTY、exec、SFTP）+ 反向隧道 + 本机 SOCKS5 监听
- **relay**（Go 单文件，工作站在跑）：SSH 端口透传、SOCKS 网关、Web 控制台、SQLite 审计

## 构建

```bash
make build          # 生成 bin/agent 和 bin/relay
```

交叉编译（在开发机上打目标平台包）：

```bash
GOOS=linux GOARCH=amd64 go build -o relay-linux-amd64 ./cmd/relay
GOOS=linux GOARCH=amd64 go build -o agent-linux-amd64 ./cmd/agent
GOOS=linux GOARCH=arm64 go build -o agent-linux-arm64 ./cmd/agent
```

## 快速开始

**1. 启动工作站中继**（工作站需能被目标机访问）：

```bash
./bin/relay \
  -listen 0.0.0.0:9443 \
  -advertise 工作站IP:9443 \
  -data-dir /opt/ssh-relay/data \
  -web-listen 127.0.0.1:8080 \
  -agent-binary /opt/ssh-relay/agent
```

首次启动会生成 CA、Web 控制台 token（打印在日志里）、Web 终端专用密钥。

> 多人使用：用启动日志里的平台 token 登录后，先在"用户管理"里创建账号，
> 之后成员用账号密码登录。

**2. 打开 Web 控制台**（`http://工作站:8080`），登录后"添加服务器"，
复制页面给出的安装命令。

**3. 在每台目标机上执行安装命令**（一次性操作：经堡垒机 → su 到你的用户后运行）。
脚本会自动下载 agent、把 Web 终端公钥写入 `~/.ssh/authorized_keys`、
安装 systemd user 服务并启动。

**4. 本地 ssh config**：

```
Host srv1
    HostName 工作站IP
    Port 22001
    User 你的用户名
    IdentityFile ~/.ssh/id_ed25519
```

之后 `ssh srv1`、`scp file srv1:~/`、`rsync -av ./ srv1:~/x/` 直接可用。

## Web 控制台功能

- 服务器增删、在线/离线状态、Agent 版本、最后心跳
- 停用/启用（立即断隧道并拒绝重连）、手动重连
- Web 终端（xterm.js，复用同一条隧道）
- Agent 在线升级（SSH 执行升级脚本：下载→SHA256 校验→换二进制→自动重启）
- 反向 SOCKS 开关（每台独立，默认关）
- 审计日志：连接事件、终端会话、代理访问、管理操作

## 安全要点

- relay 与 agent 之间 TLS，agent 固定 CA 指纹；每台 agent 独立 token（数据库只存哈希）
- SSH 中继端口绑工作站对外网卡，防火墙只放行你的 IP；SSH 公钥认证兜底
- Web 控制台登录 token；正式使用建议用 nginx + HTTPS 反代
- 代理开关默认关、按需开，代理目标全部记日志

## 多人使用说明

- **登录**：成员用用户名+密码；平台 token 仍可作为管理员兜底
- **角色**：管理员（管理用户/服务器/升级/代理开关），成员（连接、终端、日志）
- **默认用户**：每台服务器可设置一个目标机 OS 用户（Web 里"设置"，
  可先"列出目标机用户"再选择）；设置后所有会话通过 `sudo -u <用户>` 执行，
  命令/文件归属到该 OS 账户。目标机需为 Agent 所在账户配置对应 sudoers
- **用户密钥**：管理员在"用户管理"里为成员添加公钥，平台自动下发到所有 Agent；
  成员可用自己的密钥 `ssh -p 端口 用户名@工作站`
- **审计**：所有终端会话、管理操作按用户记录

## Agent 在线升级

Web 控制台每台服务器有"升级"按钮：中继通过 Web 终端密钥 SSH 进目标机，
下载新版本、校验 SHA256、替换二进制并自动重启（systemd / nohup 都兼容）。
升级期间该服务器会短暂离线（约 1-2 秒）后自动重连。

要求：目标机 `authorized_keys` 里已有 Web 终端公钥（安装脚本会自动加）。

## 项目结构

```
cmd/agent/          # 目标机端二进制入口（含 install 子命令）
cmd/relay/          # 工作站端二进制入口（中继 + Web）
internal/tunnel/    # 帧协议、多路复用、TLS/CA
internal/agent/     # SSH 服务器、SOCKS5、安装/保活
internal/relay/     # 注册中心、网关、SQLite、API、Web 页面
docs/DEPLOY.md      # 部署与引导指南
PLAN.md             # 技术计划与实现状态
```

## 开发

```bash
go test ./...
```

本地联调：同一台机器上分别启动 relay 和 agent，`ssh -p 22001 本机` 即可验证整条链路。

## 第三方组件

- [xterm.js](https://xtermjs.org/)（Web 终端渲染，MIT License），位于
  `internal/relay/static/vendor/`（未修改，已去 minified 版）。许可证全文见
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
