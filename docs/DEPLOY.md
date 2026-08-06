# 部署指南

## 一、工作站（中继）部署

推荐用 systemd 管理，二进制放 `/opt/ssh-relay/`：

```ini
# /etc/systemd/system/ssh-relay.service
[Unit]
Description=Causeway Relay
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/opt/ssh-relay/relay \
  -listen 0.0.0.0:9443 \
  -advertise 你的工作站IP:9443 \
  -data-dir /opt/ssh-relay/data \
  -web-listen 127.0.0.1:8080 \
  -web-token 换成你自己的token \
  -agent-binary /opt/ssh-relay/agent
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp bin/relay bin/agent /opt/ssh-relay/
sudo systemctl daemon-reload && sudo systemctl enable --now ssh-relay
journalctl -u ssh-relay -f
```

### 防火墙

SSH 中继端口（默认 22001 起）只放行你的 IP：

```bash
# ufw 示例
sudo ufw allow from 你的IP to any port 22001:22099 proto tcp
sudo ufw allow 9443/tcp          # agent 反向连接端口（按需限制源）
```

### Web 控制台

- 默认绑 `127.0.0.1:8080`；要用浏览器远程访问，建议加 nginx 反代 + HTTPS：
  `proxy_pass http://127.0.0.1:8080;` 并配证书
- 登录 token 由 `-web-token` 指定，首次不指定会自动生成并打印

## 二、目标机引导（一次性）

每台目标机只需要一次手工操作，之后与堡垒机无关：

1. 本地 `ssh 堡垒机`，再从堡垒机 `ssh 目标机`，`su - 你的用户名`
2. 在 Web 控制台"添加服务器"，复制安装命令
3. 在目标机**你的用户**下执行该命令

安装脚本会自动完成：下载 agent 和 CA、把 Web 终端公钥追加到
`~/.ssh/authorized_keys`、写入配置、安装并启动 systemd user 服务。

验证：

```bash
ssh -p 22001 你的用户名@工作站IP whoami
```

### 保活说明

- 优先使用 systemd user 服务（`ops-agent.service`），掉线自动拉起
- 若 `systemctl --user` 不可用，`agent install` 自动回退到 nohup + crontab `@reboot`
- 建议让运维执行一次 `loginctl enable-linger 你的用户名`，
  使未登录时 systemd user 服务也能运行

## 五、多人使用配置

### 1. 目标机配置 sudo（每台一次，root 执行）

Agent 所在账户需要免密切换到目标机上的各用户：

```bash
# 允许 Agent 账户切换到指定用户（推荐）
echo '你的用户名 ALL=(alice,bob) NOPASSWD: ALL' > /etc/sudoers.d/sshrelay
# 或小团队图省事
echo '你的用户名 ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/sshrelay
chmod 440 /etc/sudoers.d/sshrelay
```

### 2. 设置默认用户

Web 控制台 → 服务器 → 默认用户"设置"→ 列出目标机用户 → 选择保存。
之后所有会话以该 OS 用户身份执行（`sudo -u <用户>`）。

### 3. 用户与密钥

- 管理员用平台 token 登录 → "用户管理"创建账号（成员/管理员）
- 为成员添加其 SSH 公钥，平台自动下发给所有 Agent
- 成员用账号密码登录 Web；SSH 直连用自己的密钥：
  `ssh -p 22001 用户名@工作站IP`

### 常见问题

- **Web 终端连不上**：确认目标机 `~/.ssh/authorized_keys` 里有
  relay 启动日志打印的 `web terminal key`
- **Agent 一直在重连但登不上**：多半是 token 不符（Web 里重新生成安装命令会轮换 token），
  或服务器被"停用"
- **本地 SSH 提示 host key 变化**：Agent 的主机密钥持久化在 `~/.ops/agent/`，
  不要删除；重装后 `known_hosts` 里的旧条目删掉即可

## 三、反向 SOCKS（目标机借用工作站网络）

1. Web 控制台打开该服务器的"代理"开关
2. 在目标机上把程序代理指向本机 `127.0.0.1:1080`：

```bash
export https_proxy=socks5://127.0.0.1:1080
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

3. 用完后在 Web 上关闭开关；所有代理目标都会记入审计日志

## 四、密钥管理

- 目标机 `authorized_keys`：你现有的公钥（本地 SSH）+ Web 终端公钥（自动加入）
- Agent token：Web 控制台"安装命令"会轮换 token；数据库只存哈希
- 工作站 `data/` 目录含 CA、证书、密钥，务必用文件权限保护并定期备份
