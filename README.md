# mtls_shield

[English](README.en.md) | 中文

用 eBPF 在一个普通 TCP 服务的**原端口**上直接加上 mTLS，服务端代码和启动参数都不用改。

```
客户端 ──TLS:9000──▶ mtls_shield（监听原端口，OpenSSL mTLS 终结）
                              │
                              └──明文 TCP:19000──▶ 原来的普通服务
```

关键点是：原端口 9000 由 `mtls_shield` 直接监听，没有额外的 TLS 代理端口。
后端服务的 `bind(9000)` 由 eBPF `cgroup/bind4` 在系统调用层透明改写为
`127.0.0.1:19000`，所以后端仍然以为自己在监听 9000，代码和配置都不需要改。

## 设计思路

TLS 握手和证书校验必须在用户态完成，eBPF 不适合在核内做密码学。这里的职责划分是：

1. **eBPF `cgroup/bind4`**：后端进程调用 `bind(..., 9000)` 时，把端口改写为内部端口
   `19000`，并把监听地址限定到回环地址。后端进程完全无感知。
2. **`mtls_shield` 监听原端口 9000**：直接接受客户端的 TLS 连接，强制校验客户端证书。
3. **明文转发**：TLS 解密后的数据通过 `127.0.0.1:19000` 发给原服务。

客户端看到的始终只有 9000，没有第二个代理端口。

### 为什么后端一定有一个内部端口

同一个 IP/端口不能让两个进程同时监听。要在 9000 上做 TLS 终结，就必须由
`mtls_shield` 占用 9000，原来的明文服务只能退到别处。eBPF `bind4` 的价值是：

- 不用改服务代码；
- 不用改服务的监听端口配置；
- 内部端口只绑定在回环地址，不对外暴露。

如果服务本身能改成 Unix socket，也可以把内部通道换成 Unix socket，但这需要改服务。

### 可选的 redirect 模式

如果 `--listen` 指定的端口和 `--protect-port` 不同，程序会自动使用旧的重定向模式：
`mtls_shield` 监听另一个端口，eBPF `sk_lookup` + `cgroup/connect4` 把原端口的连接
透明重定向过去。默认配置不使用这个模式。

## 目录结构

```
.
├── Makefile
├── README.md
├── src
│   ├── mtls_shield.bpf.c   eBPF：cgroup/bind4（同端口模式）+ sk_lookup/connect4（redirect 模式）
│   └── mtls_shield.c       用户态：加载 eBPF、TLS 监听、mTLS 校验、双向转发
└── scripts
    ├── gen_certs.sh        生成 CA / 服务端证书 / 客户端证书 / 恶意测试证书
    ├── demo_backend.py     普通明文 HTTP 后端
    └── demo.sh             一键构建 + 启动 + 端到端测试
```

## 环境要求

- Linux 内核 >= 5.9，且启用 `CONFIG_BPF_SYSCALL`、`CONFIG_INET`、
  `CONFIG_CGROUP_BPF`
- cgroup v2
- root 权限（`CAP_BPF` + `CAP_NET_ADMIN`）
- `clang`、`bpftool`、`libbpf-dev`、`libssl-dev`、`pkg-config`、`curl`
- 目标内核有 `/sys/kernel/btf/vmlinux`（Ubuntu/Debian 默认有）

### 升级内核时必须检查的配置

替换或升级内核后，先确认下列选项。标“必须”的布尔选项需要编译进内核（`=y`），不能是模块。

| 配置 | 必需性 | 用途 |
| --- | --- | --- |
| `CONFIG_BPF` | 必须 | eBPF 基础支持 |
| `CONFIG_BPF_SYSCALL` | 必须 | `bpf()` 系统调用、libbpf 加载程序 |
| `CONFIG_CGROUPS` | 必须 | 挂载 cgroup v2 |
| `CONFIG_CGROUP_BPF` | 必须 | `cgroup/bind4`、`cgroup/connect4` 挂载点 |
| `CONFIG_NET` | 必须 | 网络子系统 |
| `CONFIG_INET` | 必须 | IPv4/TCP、`sk_lookup`、`bpf_sk_assign()`、SOCKMAP |
| `CONFIG_DEBUG_INFO_BTF` | 必须 | 生成 `/sys/kernel/btf/vmlinux`，供 `vmlinux.h` 和 CO-RE 使用 |
| `CONFIG_NET_NS` | redirect 模式/演示必须 | `sk_lookup` 挂到 netns；demo 用 netns 模拟远端客户端 |
| `CONFIG_BPF_JIT` | 建议 | 避免解释器开销 |
| `CONFIG_VETH` | 仅演示 | `demo.sh` 创建 veth pair（可为模块 `=m`） |
| `CONFIG_BPF_STREAM_PARSER` | 可选 | 仅 sockmap 流解析需要，本项目未使用 |

检查命令：

```bash
KVER=$(uname -r)
grep -E 'CONFIG_(BPF|BPF_SYSCALL|BPF_JIT|CGROUPS|CGROUP_BPF|INET|NET_NS|DEBUG_INFO_BTF|VETH|BPF_STREAM_PARSER)=' \
    /boot/config-$KVER
# 若没有 /boot/config-*：
zcat /proc/config.gz | grep -E 'CONFIG_(BPF|BPF_SYSCALL|CGROUP_BPF|INET|NET_NS|DEBUG_INFO_BTF)='

ls -l /sys/kernel/btf/vmlinux      # 必须存在
stat -fc %T /sys/fs/cgroup         # 应为 cgroup2fs
sudo bpftool feature probe kernel  # 进一步确认程序类型/helper 是否可用
```

注意：

- `CONFIG_DEBUG_INFO_BTF` 依赖编译内核时的 `CONFIG_DEBUG_INFO` 和 `pahole`，自己编译内核时最容易漏。
- cgroup 必须启用 v2 统一层级（现代发行版默认）；如被 `systemd.unified_cgroup_hierarchy=0` 或 `cgroup_no_v1` 改过，需要恢复。
- 以 root 运行，所以不需要放开非特权 BPF（`kernel.unprivileged_bpf_disabled` 可保持默认）。

### 为什么必须 >= 5.9

- `sk_lookup` 程序类型和 `bpf_sk_assign()` 辅助函数都是 **Linux 5.9 才引入**的
  （见 `src/mtls_shield.bpf.c`）。
- skeleton 会**无条件加载所有 BPF 程序**，即使同端口模式不使用 redirect，低于 5.9 的内核
  也会在加载阶段直接失败。
- 同端口模式本身只依赖 `cgroup/bind4`（4.17+），理论上可支持 4.18/5.x：用
  `bpf_program__set_autoload()` 按模式跳过 `sk_lookup`/`connect4`，或把两种模式拆成独立
  对象即可。
- 实际不建议低于 5.2：项目依赖内核 BTF（`/sys/kernel/btf/vmlinux`）生成 `vmlinux.h`，
  CO-RE 也需要它。生产环境推荐 5.10 LTS。

Ubuntu 安装依赖：

```bash
sudo apt install -y clang llvm bpftool libbpf-dev libssl-dev \
    pkg-config make gcc iproute2 curl
```

## 构建

```bash
make
```

默认会用**构建机**的 BTF 生成 `src/vmlinux.h`。但 `vmlinux.h` 只是编译期的类型来源，
加载时 libbpf 会用目标内核的 BTF 做 CO-RE 重定位，所以 BPF 对象是可移植的：
**用目标机器的 `vmlinux.h` 编译，产物就能在目标机器运行**，不要求一定在目标机器上编译。

交叉编译时，先取目标内核的 BTF 覆盖 `src/vmlinux.h`：

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h
```

（在目标机器上执行，或取得目标机的 `/sys/kernel/btf/vmlinux` 后在构建机执行。）

注意 BPF 对象和用户态程序要分开看：BPF 对象靠 CO-RE 跨内核版本，但用户态
`mtls_shield` 链接的是 libc/libbpf/libssl，必须针对目标架构和库编译，交叉编译需要
对应的工具链。另外 BPF 的 `-D__TARGET_ARCH_*` 仍应与目标架构一致。产物是 `./mtls_shield`。

## 生成证书

```bash
HOST_IP=172.16.74.195 ./scripts/gen_certs.sh certs
```

`HOST_IP` 会写进服务端证书的 SAN。证书包括：

- `ca.crt` / `ca.key`：信任的 CA
- `server.crt` / `server.key`：服务端证书
- `client.crt` / `client.key`：合法客户端证书（CN=alice）
- `rogue-ca.*` / `rogue-client.*`：不受信任的客户端证书，用于负向测试

## 运行

**顺序很重要：先启动 `mtls_shield`，再启动原来的服务。** 因为 eBPF 必须赶在服务
`bind(9000)` 之前挂上，才能改写它的监听端口。

1. 启动 mTLS 层，占用原端口 9000：

```bash
sudo ./mtls_shield \
  --listen 0.0.0.0:9000 \
  --protect-port 9000 \
  --upstream 127.0.0.1:19000 \
  --ca certs/ca.crt \
  --cert certs/server.crt \
  --key certs/server.key
```

默认**不限制 CN**：只要客户端证书能链到 `--ca` 指定的 CA，并且证书在有效期内，
任何 CN 都会被接受。只有显式传入 `--allow-cn` 才会启用 CN 白名单。
上面的命令如果加 `--allow-cn alice`，就只允许 CN=alice。

2. 再启动原来的服务。它仍然按原配置监听 9000：

```bash
python3 scripts/demo_backend.py --host 127.0.0.1 --port 9000
```

eBPF 会把它实际的监听地址改成 `127.0.0.1:19000`。可以验证：

```bash
ss -ltnp | grep -E ':(9000|19000)'
# mtls_shield 监听 0.0.0.0:9000
# python3     监听 127.0.0.1:19000
```

3. 客户端仍然访问 9000，但实际是 mTLS：

```bash
curl --cacert certs/ca.crt \
     --cert certs/client.crt \
     --key certs/client.key \
     https://172.16.74.195:9000/
```

不带客户端证书：

```bash
curl --cacert certs/ca.crt https://172.16.74.195:9000/
# 握手失败
```

直接用明文访问原端口：

```bash
curl http://172.16.74.195:9000/
# 握手失败
```

内部后端仍然是明文：

```bash
curl http://127.0.0.1:19000/
# 200，证明原服务没有改动
```

### 一键演示

脚本会构建、生成证书、**先启动 shield 再启动后端**，并验证：

- eBPF 把后端的 bind 从 9000 改写到 19000
- 原端口上的 mTLS 成功
- 无客户端证书、非信任 CA、明文 HTTP 被拒绝
- 1 MiB 响应和 256 KiB 请求的转发
- 从独立 netns 模拟远端客户端访问原端口

```bash
sudo ./scripts/demo.sh
```

## 参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-l, --listen ADDR:PORT` | `0.0.0.0:9000` | mTLS 监听地址；和 `--protect-port` 相同即同端口模式 |
| `-p, --protect-port PORT` | `9000` | 原始 TCP 端口 |
| `-u, --upstream ADDR:PORT` | `127.0.0.1:19000` | 内部明文服务地址，也是 bind 改写目标 |
| `-n, --protect-cidr CIDR` | 所有本机 IPv4 地址 | 仅 redirect 模式使用 |
| `-a, --ca FILE` | `certs/ca.crt` | 客户端证书 CA |
| `-c, --cert FILE` | `certs/server.crt` | 服务端证书链 |
| `-k, --key FILE` | `certs/server.key` | 服务端私钥 |
| `-C, --allow-cn CN` | 不限制 | 允许的客户端证书 CN，可重复 |
| `-t, --handshake-timeout SEC` | `10` | TLS 握手超时 |
| `-m, --max-conns N` | `512` | 最大并发连接数 |
| `-P, --pool-size N` | `32` | 预连接 upstream 的连接池大小；`0` 关闭 |
| `-L, --no-local-redirect` | 关闭该开关 | redirect 模式下不挂 `cgroup/connect4` |
| `-v, --verbose` | 关闭 | 打印 libbpf 调试日志 |
| `-h, --help` | | 帮助 |

启动后给进程发 `SIGUSR1` 可以打印 BPF 统计：

```bash
sudo kill -USR1 <pid>
```

统计项：

- `bind_redirect`：同端口模式下，被改写的后端 `bind()` 次数
- `sk_lookup_redirect` / `connect_redirect`：redirect 模式下的重定向次数
- `no_proxy_socket` / `assign_error`：redirect 模式的异常计数
- `sk_lookup_seen` / `port_match`：调试计数
- upstream pool：连接池命中/未命中次数（`hits` / `misses`）

## upstream 连接池

`src/mtls_shield.c` 内置一个预连接池，后台线程持续保持 `--pool-size` 条到
`--upstream` 的已连接 socket。新客户端完成 mTLS 握手后直接从池中取一条可用连接，
省去 `socket()/connect()/poll()` 的握手延迟；池空时自动回退为同步连接，因此不会
因为池大小限制并发。取出前会用 `MSG_PEEK` 做存活检查，后端已关闭或重置的连接会被
丢弃并补充。会话结束后连接直接关闭，不在客户端之间复用，避免任意 TCP 协议的
数据串流问题。

高并发建议：

- `--pool-size` 设为预估的瞬时新建连接速率，通常 32–256 即可；过大会占用后端
  的 accept 队列和连接资源。
- 连接池只消除 upstream 建连开销，代理仍是每连接一线程。需要上万并发连接时，
  应进一步改成 epoll 事件驱动 + 线程池。

## 安全说明

- 只接受 TLS 1.2 及以上。
- 必须提供客户端证书（`SSL_VERIFY_FAIL_IF_NO_PEER_CERT`）。
- 客户端证书必须能链到 `--ca` 指定的 CA。
- 可选 `--allow-cn` 做第二层身份白名单。
- 明文客户端会直接握手失败，无法绕过 mTLS。
- eBPF 把后端监听地址强制改写到回环地址，外部无法直接访问明文后端。
- 代理日志会记录客户端地址和证书 CN，但不会记录私钥或明文应用数据。

## 限制

- 目前只处理 IPv4；IPv6 需要增加 `cgroup/bind6` 和 IPv6 map/program。
- 必须先启动 shield，再启动服务。服务启动后再挂 eBPF 无法追改已经完成的 `bind()`。
- 同端口模式下后端服务的 `getsockname()` 会看到真实内部端口 19000；`bind4` 只改
  `bind()` 的入参，无法隐藏内核 socket 的真实绑定。如果服务会把监听端口写进响应
  或做自连接，可以改用 redirect 模式绕开：
  `--listen 0.0.0.0:8443 --protect-port 9000 --upstream 127.0.0.1:9000`。
  此时不挂 `bind4`，后端仍绑定 `0.0.0.0:9000`，`getsockname()` 返回原始值。代价
  是多一个监听端口，且本机 `127.0.0.1:9000` 会绕过 mTLS（上游地址不能纳入保护
  网段，否则代理连上游会死循环）。若必须保留同端口模式，可在用户态用 LD_PRELOAD
  重写 `getsockname()`，或在内核用 kretprobe + `bpf_probe_write_user` 改写返回值
  （本项目未实现）。
- `cgroup/bind4` 挂在 `/sys/fs/cgroup`，会改写所有后续对原端口的 `bind()`。
  生产环境建议把后端放进独立 cgroup，并把程序挂到该 cgroup 上。
- mTLS 在代理处终结，代理到后端是回环明文。
- 没有实现 SNI 路由、TLS 透传、CRL/OCSP。
- 每个连接一个线程；upstream 连接池只减少建连开销，不改变线程模型。需要
  上万并发连接时应改成 epoll 事件驱动 + 线程池。
- redirect 模式仍然保留，但默认不使用。

## 排障

```bash
# 确认 bind4 / sk_lookup 已加载
sudo bpftool link list
sudo bpftool prog show name shield_bind4

# 查看监听：9000 应该是 mtls_shield，19000 应该是原服务
ss -ltnp | grep -E ':(9000|19000)'

# 查看代理日志
tail -f demo.log
```

常见问题：

- **启动报 `bind 0.0.0.0:9000: Address already in use`**：后端先启动了。
  先停后端，启动 `mtls_shield`，再启动后端。程序日志里也会给出这个提示。
- **后端还在 9000**：确认 `ss` 显示后端在 19000；如果不在，说明 `bind4` 没挂上，
  或后端启动早于 shield。
- **curl 报证书主机名不匹配**：生成证书时 `HOST_IP` 没包含访问用的 IP。
- **远端访问不到**：确认 `--listen 0.0.0.0:9000`，防火墙放行 9000。
- **`--allow-cn` 不生效**：确认证书的 Subject CN 就是配置的值。
- **端口/资源残留**：进程退出时会 detach eBPF link；`bpftool link list` 里不应再有
  对应的 `bind4`/`sk_lookup`。

## 许可证

本项目基于 [WTFPL](LICENSE)（Do What The Fuck You Want To Public License）发布。
