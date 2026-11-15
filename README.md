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

### 多进程模型

端口、上游和证书都以逗号分隔的列表传入，列表下标就是实例编号。主进程只加载一次
eBPF、创建所有监听 socket，然后为每个端口 fork 一个转发子进程；子进程负责该端口的
TLS 握手、证书校验和明文转发。主进程不处理连接，只做监督：子进程异常退出时按退避
重启，父进程被杀死时子进程通过 `PR_SET_PDEATHSIG` 一起退出。eBPF 配置表按原端口
索引，因此各实例可以独立选择同端口模式或 redirect 模式。

### 为什么后端一定有一个内部端口

同一个 IP/端口不能让两个进程同时监听。要在 9000 上做 TLS 终结，就必须由
`mtls_shield` 占用 9000，原来的明文服务只能退到别处。eBPF `bind4` 的价值是：

- 不用改服务代码；
- 不用改服务的监听端口配置；
- 内部端口只绑定在回环地址，不对外暴露。

如果服务本身能改成 Unix socket，也可以把内部通道换成 Unix socket，但这需要改服务。

### 可选的 redirect 模式

如果某个实例的 `--listenport` 和它的 `--protect_port` 不同，该实例会自动使用旧的重定向模式：
`mtls_shield` 监听另一个端口，eBPF `sk_lookup` + `cgroup/connect4` 把原端口的连接
透明重定向过去。不同实例可以分别选择同端口模式或 redirect 模式。默认配置使用同端口模式。

### 同端口模式（默认）

当某个实例的 `--listenport` 等于它的 `--protect_port` 时，程序对该实例使用同端口模式。
完整流程示例（把 `bind4` 收窄到后端专属 cgroup，推荐）：

```bash
# 1) 建一个只给后端用的 cgroup（cgroup v2 统一层级）
sudo mkdir -p /sys/fs/cgroup/mtls-backend

# 2) 先启动 shield：占用 9000，把后端的 bind(9000) 改写到 127.0.0.1:19000
sudo ./mtls_shield \
  --listenport 9000 \
  --protect_port 9000 \
  --upstream 127.0.0.1:19000 \
  --ca certs/ca.crt --cert certs/server.crt --key certs/server.key \
  --bind-cgroup /sys/fs/cgroup/mtls-backend

# 3) 后端必须在 shield 之后启动，并在 bind() 之前进入同一个 cgroup
sudo sh -c 'echo $$ > /sys/fs/cgroup/mtls-backend/cgroup.procs; exec ./your-backend'

# 4) 验证：9000 属于 mtls_shield，19000 属于后端
ss -ltnp | grep -E ':(9000|19000)'
cat /proc/"$(pgrep -x your-backend)"/cgroup
```

不想收窄影响面时，去掉 `--bind-cgroup` 并跳过第 1、3 步的 cgroup 操作即可，后端照常
直接启动（此时 `bind4` 挂在 `/sys/fs/cgroup` 根，所有后代 cgroup 都会生效）。

工作流程：

1. 主进程先 bind 所有监听端口，再加载一次 eBPF、写入按端口索引的配置，并给每个端口
   fork 一个转发子进程。
2. 用户态把 `cgroup/bind4` 挂到一个 cgroup（默认 `/sys/fs/cgroup`，可用
   `--bind-cgroup` 收窄到后端专属 cgroup）。
3. 后端按原配置 `bind(9000)`；`bind4` 在系统调用层把参数改成 `127.0.0.1:19000`，后端无感知。
4. 对应的转发子进程把解密后的明文通过 `127.0.0.1:19000` 发给后端。

9000 由代理占用，后端被挪到内部端口且限制在回环地址，因此外部即使知道 19000 也连不上。
主进程负责监督子进程：子进程异常退出时按 1s 起步、最长 30s 的退避重启。

前置条件与约束：

- 必须先启动 `mtls_shield`，再启动后端；否则后端会因 `EADDRINUSE` 启动失败。
- 同端口实例的 `--upstream` 必须是本机地址，且端口不能等于该实例的 `--protect_port`。
- `bind4` 只改写配置表里同端口实例的 `bind()`，其他端口（metrics、debug 等）不受影响；redirect 实例的 `bind()` 也不会被改写。
- `bind4` 默认挂在 `/sys/fs/cgroup` 根，覆盖所有后代 cgroup；生产环境建议用
  `--bind-cgroup` 挂到后端专属 cgroup，避免其他进程的同端口 `bind()` 被改写，见下文。
- 仅 IPv4；需要 cgroup v2、root、`CONFIG_CGROUP_BPF`。`bind4` 本身 4.17+ 可用，但 skeleton 会无条件加载 `sk_lookup`，所以实际仍要求 >= 5.9。
- 没有任何 redirect 实例时，`--protect-cidr` 被忽略。
- 后端调用 `getsockname()` 会看到内部端口 19000，处理方式见“限制”一节。

适合使用的场景：

- 希望客户端只看到原端口，不额外暴露代理端口。
- 后端代码和启动参数都不能改，或不想改。
- 后端是普通 TCP/HTTP 服务，启动时监听 `0.0.0.0:<原端口>`。
- 能保证“先 shield、后服务”的启动顺序；服务在 shield 运行期间重启仍会被改写。
- 希望后端只存在于回环地址，提供比 redirect 模式更强的“明文后端不可从外部直连”保证。
- 后端不依赖 `getsockname()` 做自我上报或自连接，或能接受/绕过 19000 的差异。

不适合或需要谨慎：

- 服务用 `getsockname()` 把监听端口写进状态接口。
- 服务在 shield 启动前就已完成 `bind()`，eBPF 无法追改。
- 后端不在 `bind4` 生效的 cgroup 范围内。
- 纯 IPv6 服务。
- 服务需要多个进程同时绑同一端口，或有特殊的 `SO_REUSEPORT` 依赖。

### 把 `bind4` 限定到后端专属 cgroup

`bind4` 只改写配置表里 `--protect_port` 对应端口的 `bind()`，但挂载点是
`/sys/fs/cgroup` 根时，同一台机器上其他 cgroup 里同样 `bind(9000)` 的进程也会被
改写（例如别的租户或别的服务容器）。用 `--bind-cgroup` 收窄挂载点即可：

```bash
# 1. 给后端建一个专属 cgroup（cgroup v2 统一层级，root 权限）
mkdir -p /sys/fs/cgroup/mtls-backend

# 2. 先启动 shield，把 bind4 挂到该 cgroup
sudo ./mtls_shield \
  --listenport 9000 --protect_port 9000 --upstream 127.0.0.1:19000 \
  --ca certs/ca.crt --cert certs/server.crt --key certs/server.key \
  --bind-cgroup /sys/fs/cgroup/mtls-backend

# 3. 后端在 bind() 之前进入该 cgroup
echo "$BACKEND_PID" > /sys/fs/cgroup/mtls-backend/cgroup.procs
# 或直接在 cgroup 内启动：
#   sh -c 'echo $$ > /sys/fs/cgroup/mtls-backend/cgroup.procs; exec ./backend'
```

要点：

- 程序对挂载的 cgroup **及其所有后代**生效；先挂载、后把后端移进来也可以，只要
  后端还没执行 `bind()`。
- 不要把 shield 自己（和它的转发子进程）放进这个 cgroup：接口/进程重启时需要重新
  `bind()`，届时端口会被改写到内部端口。目标 cgroup 里只放后端进程树。
- 路径必须在挂载时已存在、且是目录，否则启动直接报错。用 systemd 托管后端时，
  可以直接指向它的 unit cgroup，例如
  `/sys/fs/cgroup/system.slice/my-backend.service`。
- `cgroup/bind4` 只在 cgroup v2 统一层级下可用；`--connect-cgroup` 同理只影响
  redirect 模式的 `cgroup/connect4`，默认仍是 `/sys/fs/cgroup`（本机客户端可能
  分布在任意 cgroup，通常不需要收窄）。
- shield 退出时会自动卸载程序；有程序挂载期间 cgroup 目录不能 `rmdir`（`EBUSY`），
  清理顺序应为先停 shield 再删 cgroup。

同端口模式与 redirect 模式的对比：

| | 同端口模式 | redirect 模式 |
| --- | --- | --- |
| 判定 | `listen_port == protect_port` | `listen_port != protect_port` |
| eBPF | 该端口使用 `cgroup/bind4` | 该端口使用 `sk_lookup` + `cgroup/connect4` |
| 后端端口 | 改写到 `--upstream` | 保持原端口 |
| `getsockname()` | 看到内部端口 19000 | 看到原端口 9000 |
| 额外监听端口 | 无 | 有 |
| 启动顺序 | 必须先启动 shield | 无严格要求 |
| 后端暴露面 | 仅回环 | 绑 `0.0.0.0`，靠 `sk_lookup` 拦截 |

简单选择：要“端口干净、后端藏起来”用同端口模式；要“后端状态自报正确、启动顺序随意”用 redirect 模式。

## 目录结构

```
.
├── Makefile
├── README.md
├── src
│   ├── mtls_shield.bpf.c   eBPF：cgroup/bind4（同端口模式）+ sk_lookup/connect4（redirect 模式）
│   └── mtls_shield.c       用户态：主进程加载 eBPF 并监督，每端口一个转发子进程
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
- `clang`、`bpftool`、`libbpf-dev`、`libssl-dev`、`libelf-dev`、`zlib1g-dev`、`pkg-config`、`curl`
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
| `CONFIG_INET` | 必须 | IPv4/TCP、`sk_lookup`、`bpf_sk_assign()`、SOCKHASH |
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
    libelf-dev zlib1g-dev pkg-config make gcc iproute2 curl

# OpenSSL 3.5+（Ubuntu 26.04、Debian trixie 起）静态链接还需要静态 jitterentropy：
sudo apt install -y libjitterentropy3-dev
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

默认构建是**全静态链接**（`STATIC=1`），产物不受目标机 glibc 版本限制；取舍、限制和
验证方法见下一章「静态链接与 glibc 兼容性」。

## 静态链接与 glibc 兼容性

### 为什么默认静态链接

动态链接的产物在目标机上依赖 `libc.so.6` 的符号版本，遇到较旧的发行版会直接报
`version 'GLIBC_2.xx' not found`。本项目默认全静态链接（`STATIC=1`），把
`libc`、`libssl`、`libcrypto`、`libbpf`、`libelf`、`libz` 全部链进二进制，
`mtls_shield` 因此不再受目标机 glibc 版本约束。

### 构建与验证

```bash
make            # 全静态（默认）
make STATIC=0   # 动态链接，本地调试用
make verify     # 校验产物
```

`make verify` 检查两件事：

- `file ./mtls_shield` 输出 `statically linked`
- `readelf -V ./mtls_shield` 中没有任何 `GLIBC_` 符号版本需求

静态库来自各发行版的 `-dev` 包：`libbpf.a`（`libbpf-dev`）、`libelf.a`（`libelf-dev`）、
`libz.a`（`zlib1g-dev`）、`libssl.a` / `libcrypto.a`（`libssl-dev`）。
OpenSSL 3.5+ 还会额外要求静态 jitterentropy（`libjitterentropy.a`，来自
`libjitterentropy3-dev`），否则报 `cannot find -l:libjitterentropy.a`。
缺少时会报 `cannot find -lxxx`，装上对应包即可。

### 为什么 OpenSSL 3.5+ 还要装 `libjitterentropy3-dev`

Ubuntu 26.04（OpenSSL 3.5.5）上静态链接会报：

```text
ld: cannot find -l:libjitterentropy.a
have you installed the static version of the :libjitterentropy.a library ?
```

原因链：

1. OpenSSL 3.5 起，`libcrypto.pc` 的 `Libs.private` 里带上 `-l:libjitterentropy.a`；
2. `make` 默认全静态，`pkg-config --libs --static openssl` 会把它原样带进链接命令；
3. 但 `libssl-dev` 不包含这个静态库，它由 `libjitterentropy3-dev` 提供；
4. 缺这个库，`ld` 直接失败。

这不是代码或 Makefile 的问题，装上即可：

```bash
sudo apt install -y libjitterentropy3-dev
```

旧系统（Ubuntu 22.04/24.04 对应的 OpenSSL 3.0/3.2）没有这个静态依赖，不会遇到。

### 静态 glibc 的限制

- **`getaddrinfo` 依赖目标机的 NSS 模块。** 静态 glibc 解析域名要 `dlopen`
  `libnss_dns.so.2` / `libnss_files.so.2`，目标机版本不匹配时解析会失败。
  所以静态构建带 `-DMTLS_STATIC_BUILD`，用 `AI_NUMERICHOST` 编译，
  **`--upstream` 只接受 IP 字面量**，写域名会在启动阶段报
  `cannot resolve upstream host`。（`--listenport` 本来就用 `inet_pton` 校验，只接受 IP。）
- `dlopen`、NSS 插件（LDAP/SSSD 等）、`getpwnam` 一类接口在静态 glibc 下不可靠；
  本项目未使用。
- **安全更新需要重新发布。** glibc / OpenSSL 的 CVE 修复无法通过目标机系统升级获得，
  必须重新编译并分发二进制。
- **只解决 libc 兼容性。** 内核要求（>= 5.9、`CONFIG_DEBUG_INFO_BTF`、cgroup v2）
  与静态链接无关，仍需逐项确认，见「环境要求」。
- **License。** glibc 是 LGPL，对外分发静态二进制时需提供可重新链接的方式
  （目标文件或源码）；仅内部部署无此顾虑。OpenSSL 3 是 Apache-2.0。

### 其他可选方案

如果以后全静态不再合适，可以考虑下面的替代路线（当前采用的是表中的第一行）：

| 方案 | glibc 兼容 | 域名解析 | 说明 |
| --- | --- | --- | --- |
| `-static` + 系统 glibc（当前） | 通吃 | 仅 IP | 改动最小 |
| 旧 glibc 容器内动态构建（如 CentOS 7 / glibc 2.17） | 下限 2.17 | 正常 | 兼容面广，需维护构建镜像 |
| musl 静态（Alpine / `zig cc -target x86_64-linux-musl`） | 完全自包含 | 正常（musl 自带 resolver） | 需自行静态编译 libbpf/openssl |

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
  --listenport 9000 \
  --protect_port 9000 \
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
| `-l, --listenport LIST` | 必填 | mTLS 监听端口，逗号分隔，列表下标即实例编号 |
| `-p, --protect_port LIST` | 同 `--listenport` | 原始 TCP 端口，逗号分隔，个数必须与端口数相同；省略则复用 `--listenport` |
| `-u, --upstream LIST` | 必填 | 内部明文服务地址，按实例下标一一对应，个数必须与端口数相同 |
| `-H, --listen-host ADDR` | `0.0.0.0` | 所有实例共用的监听地址 |
| `-n, --protect-cidr CIDR` | 所有本机 IPv4 地址 | 仅 redirect 模式使用 |
| `-a, --ca LIST` | `certs/ca.crt` | 客户端证书 CA，按实例下标对应；只给 1 个值时广播 |
| `-c, --cert LIST` | `certs/server.crt` | 服务端证书链，按实例下标对应；只给 1 个值时广播 |
| `-k, --key LIST` | `certs/server.key` | 服务端私钥，按实例下标对应；只给 1 个值时广播 |
| `-C, --allow-cn CN` | 不限制 | 允许的客户端证书 CN，可重复（对所有实例生效） |
| `-t, --handshake-timeout SEC` | `10` | TLS 握手超时 |
| `-m, --max-conns N` | `512` | 每个转发子进程的最大并发连接数 |
| `-P, --pool-size N` | `32` | 每个转发子进程的 upstream 连接池大小；`0` 关闭 |
| `-L, --no-local-redirect` | 关闭该开关 | redirect 模式下不挂 `cgroup/connect4` |
| `--bind-cgroup PATH` | `/sys/fs/cgroup` | `cgroup/bind4` 的挂载点；建议指向后端专属 cgroup |
| `--connect-cgroup PATH` | `/sys/fs/cgroup` | `cgroup/connect4` 的挂载点 |
| `-v, --verbose` | 关闭 | 额外打印每条 mTLS 连接和 libbpf 调试日志 |
| `-h, --help` | | 帮助 |

参数按数组下标对应，例如：

```bash
sudo ./mtls_shield \
  --listenport 9000,9443 \
  --protect_port 9000,9443 \
  --upstream 127.0.0.1:19000,127.0.0.1:19443 \
  --ca certs/ca.crt \
  --cert certs/server.crt,certs/server-9443.crt \
  --key certs/server.key,certs/server-9443.key
```

第 0 个实例是 `9000 -> 127.0.0.1:19000`，第 1 个实例是
`9443 -> 127.0.0.1:19443`；证书列表未写满时用单值广播。

主进程只加载一次 eBPF，并负责创建所有监听 socket、fork 每个端口的转发子进程、
在子进程异常退出时按退避策略重启。给主进程发 `SIGUSR1` 会打印 BPF 统计和各子进程
状态，并转发给子进程打印各自的连接池统计：

```bash
sudo kill -USR1 <pid>
```

统计项：

- `bind_redirect`：同端口模式下，被改写的后端 `bind()` 次数
- `sk_lookup_redirect` / `connect_redirect`：redirect 模式下的重定向次数
- `no_proxy_socket` / `assign_error`：redirect 模式的异常计数
- `sk_lookup_seen` / `port_match`：调试计数
- upstream pool：连接池命中/未命中次数（`hits` / `misses`）

BPF 统计通过 ringbuf 事件送到用户态累加（`BPF_MAP_TYPE_RINGBUF`，256 KiB），
主进程在 supervise 循环里持续消费。ringbuf 满时事件会被丢弃，因此这些数值是
“用户态观察到的事件数”，不是严格计数；正常连接速率下不会丢。

日志全部写到 stderr，每条一行、带毫秒时间戳和来源标签（`main` 或 `w<实例>:<监听端口>`）：

```text
2026-11-14 06:32:26.938 [main] INFO  daemon ready: 1 instance(s)
2026-11-14 06:32:26.941 [w0:9444] INFO  worker #0 pid=1234 starting: take over tcp/9443, mTLS on 0.0.0.0:9444, forward to 127.0.0.1:19000 (redirect)
2026-11-14 06:32:26.943 [w0:9444] INFO  ready: accepting mTLS connections
2026-11-14 06:32:28.935 [w0:9444] ERROR TLS handshake from 10.0.0.9:50000 failed: error:0A0000C7:SSL routines::peer did not return a certificate
```

- 默认只输出 `INFO`/`WARN`/`ERROR`；`--verbose` 追加 `DEBUG`（每条成功连接、libbpf 细节）。
- 终端上按级别着色，重定向到文件或管道时自动关闭颜色，便于 `grep`/日志采集。
- 每条日志由一次 `write(2)` 写出，父进程和多个子进程同时写同一个日志文件也不会交错。
- 过载时 `connection limit reached` 每秒最多一行，并带上这一秒内拒绝的连接数。

## upstream 连接池

每个转发子进程各有一个预连接池，后台线程持续保持 `--pool-size` 条到该实例
`--upstream` 的已连接 socket。新客户端完成 mTLS 握手后直接从池中取一条可用连接，
省去 `socket()/connect()/poll()` 的握手延迟；池空时自动回退为同步连接，因此不会
因为池大小限制并发。取出前会用 `MSG_PEEK` 做存活检查，后端已关闭或重置的连接会被
丢弃并补充。会话结束后连接直接关闭，不在客户端之间复用，避免任意 TCP 协议的
数据串流问题。

高并发建议：

- `--pool-size` 设为预估的瞬时新建连接速率，通常 32–256 即可；过大会占用后端
  的 accept 队列和连接资源。
- 连接池只消除 upstream 建连开销，代理仍是“每端口一个进程 + 每连接一线程”。
  `--max-conns` 和 `--pool-size` 都按子进程生效。需要上万并发连接时，
  应进一步改成 epoll 事件驱动 + 线程池。

## 安全说明

- 只接受 TLS 1.2 及以上。
- 必须提供客户端证书（`SSL_VERIFY_FAIL_IF_NO_PEER_CERT`）。
- 客户端证书必须能链到 `--ca` 指定的 CA。
- 可选 `--allow-cn` 做第二层身份白名单。
- 明文客户端会直接握手失败，无法绕过 mTLS。
- eBPF 把后端监听地址强制改写到回环地址，外部无法直接访问明文后端。
- 默认只记录启动、连接失败、重连等关键事件；`--verbose` 会额外记录每个客户端的
  地址和证书 CN。任何时候都不会记录私钥或明文应用数据。

## 限制

- 目前只处理 IPv4；IPv6 需要增加 `cgroup/bind6` 和 IPv6 map/program。
- 必须先启动 shield，再启动服务。服务启动后再挂 eBPF 无法追改已经完成的 `bind()`。
- 同端口模式下后端服务的 `getsockname()` 会看到真实内部端口 19000；`bind4` 只改
  `bind()` 的入参，无法隐藏内核 socket 的真实绑定。如果服务会把监听端口写进响应
  或做自连接，可以改用 redirect 模式绕开：
  `--listenport 8443 --protect_port 9000 --upstream 127.0.0.1:9000`。
  此时该实例不挂 `bind4`，后端仍绑定 `0.0.0.0:9000`，`getsockname()` 返回原始值。代价
  是多一个监听端口，且本机 `127.0.0.1:9000` 会绕过 mTLS（上游地址不能纳入保护
  网段，否则代理连上游会死循环）。若必须保留同端口模式，可在用户态用 LD_PRELOAD
  重写 `getsockname()`，或在内核用 kretprobe + `bpf_probe_write_user` 改写返回值
  （本项目未实现）。
- `cgroup/bind4` 默认挂在 `/sys/fs/cgroup`，会改写该层级内所有后续对原端口的
  `bind()`。生产环境建议把后端放进独立 cgroup，并用 `--bind-cgroup` 把程序挂到
  该 cgroup 上。
- mTLS 在代理处终结，代理到后端是回环明文。
- 没有实现 SNI 路由、TLS 透传、CRL/OCSP。
- 每个连接一个线程；upstream 连接池只减少建连开销，不改变线程模型。需要
  上万并发连接时应改成 epoll 事件驱动 + 线程池。
- redirect 模式仍然保留，但默认不使用。
- 静态构建下 `--upstream` 只接受 IP 字面量，不支持域名
  （见「静态链接与 glibc 兼容性」）；`make STATIC=0` 的动态构建可以用域名。

## 排障

```bash
# 确认 bind4 / sk_lookup 已加载
sudo bpftool link list
sudo bpftool prog show name shield_bind4

# 确认 bind4 挂在了预期的 cgroup（默认是 /sys/fs/cgroup 根）
sudo bpftool cgroup tree /sys/fs/cgroup

# 查看监听：9000 应该是 mtls_shield，19000 应该是原服务
ss -ltnp | grep -E ':(9000|19000)'

# 查看代理日志
tail -f demo.log
```

常见问题：

- **启动报 `bind 0.0.0.0:9000: Address already in use`**：后端先启动了。
  先停后端，启动 `mtls_shield`，再启动后端。程序日志里也会给出这个提示。
- **后端还在 9000**：确认 `ss` 显示后端在 19000；如果不在，说明 `bind4` 没挂上、
  后端启动早于 shield，或后端不在 `--bind-cgroup` 指定的 cgroup 内
  （用 `cat /proc/<pid>/cgroup` 对照）。
- **用 `systemd-run --scope --unit=xxx` 启动后端仍报 `EADDRINUSE`**：`--unit=` 只是
  systemd 单元名，进程实际落在 `/sys/fs/cgroup/system.slice/xxx.scope`，并不在
  `--bind-cgroup` 指定的目录里，所以 `bind4` 不生效。要保留 systemd 的资源限制，可以
  用 slice 对齐范围：
  `sudo systemctl start testgroup.slice`，让 shield 挂到
  `/sys/fs/cgroup/testgroup.slice`，再用
  `sudo systemd-run --scope --slice=testgroup.slice ...` 启动后端（scope 会成为该
  slice 的子 cgroup）；或者按上文示例手动把 PID 写进 `cgroup.procs`。
- **curl 报证书主机名不匹配**：生成证书时 `HOST_IP` 没包含访问用的 IP。
- **远端访问不到**：确认 `--listen-host 0.0.0.0` 且防火墙放行对应端口。
- **`--allow-cn` 不生效**：确认证书的 Subject CN 就是配置的值。
- **端口/资源残留**：进程退出时会 detach eBPF link；`bpftool link list` 里不应再有
  对应的 `bind4`/`sk_lookup`。
- **链接报 `cannot find -l:libjitterentropy.a`**：OpenSSL 3.5+ 的 `libcrypto.pc` 把静态
  jitterentropy 列为依赖，装 `libjitterentropy3-dev` 即可（Ubuntu 26.04、Debian trixie 起）。
  用 `make STATIC=0` 动态链接也可以绕过。

## 许可证

本项目基于 [WTFPL](LICENSE)（Do What The Fuck You Want To Public License）发布。
