/*
 * =====================================================================================
 *  mtls_shield 学习注释版（study_mtls_shield_annotated.c）
 * =====================================================================================
 *
 *  【本文件用途】
 *  这是一个"供阅读学习"的注释版代码文件，把 mtls_shield 项目里最核心的两块逻辑：
 *      (1) eBPF 内核态程序（cgroup/bind4 端口透明改写）
 *      (2) 用户态 mTLS 代理（OpenSSL 双向 TLS + 明文转发）
 *  合并到一个文件里，逐行讲解。它【不能直接编译】，因为：
 *      - eBPF 代码和用户态代码的编译工具链不同（前者用 clang -target bpf）
 *      - 这里省略了日志、参数解析等次要辅助函数
 *  想编译运行请看 src/mtls_shield.bpf.c 和 src/mtls_shield.c。
 *
 *  【架构总览】
 *
 *    客户端 ── TLS(9000) ──▶ mtls_shield (mTLS 终结)
 *                                  │
 *                                  └── 明文 TCP(127.0.0.1:19000) ──▶ 原有后端服务
 *
 *  核心难点：后端服务原本 bind(0.0.0.0:9000)，而 mtls_shield 也要监听 9000 来做
 *  TLS 终结——同一个 IP:Port 不允许两个进程同时监听！
 *
 *  解决方案：eBPF 的 cgroup/bind4 程序挂在系统调用层。当后端进程调用
 *  bind(fd, {0.0.0.0, 9000}) 时，内核里的 eBPF 程序把端口"偷偷"改成 19000、
 *  地址改成 127.0.0.1。后端进程完全无感知（它以为自己还在监听 9000），
 *  而 9000 就被腾出来给 mtls_shield 用了。
 *
 *  【涉及的关键技术点清单（学习路线图）】
 *    A. eBPF 部分
 *       A1. BPF map 的定义与种类（ARRAY / LPM_TRIE / SOCKMAP / PERCPU_ARRAY）
 *       A2. SEC("cgroup/bind4") 挂载点与 bpf_sock_addr 上下文
 *       A3. 在 bind 系统调用路径上原地修改 user_ip4/user_port
 *       A4. SEC("sk_lookup") + bpf_sk_assign：把入站连接"递给"指定 socket
 *    B. 用户态部分
 *       B1. libbpf skeleton 的 open/load/attach 生命周期
 *       B2. OpenSSL SSL_CTX 配置：服务端证书 + 强制客户端证书（mTLS）
 *       B3. verify_callback：证书链校验 + CN 白名单二次校验
 *       B4. 非阻塞 connect + poll 等待（处理 EINPROGRESS）
 *       B5. poll 双向转发循环：处理半关闭、部分读写、TLS 缓冲
 *       B6. 每连接一线程模型（pthread）
 *
 * =====================================================================================
 */

/* =====================================================================================
 * 第 0 部分：公共头文件
 * -------------------------------------------------------------------------------------
 * eBPF 程序和用户态程序都会包含的定义放在这里，方便对照。
 * ===================================================================================== */

/* 用户态需要的网络/系统头文件（eBPF 侧不需要，它用 vmlinux.h） */
#include <arpa/inet.h>    /* inet_pton/htons：IP 字符串与二进制转换、字节序转换 */
#include <errno.h>        /* errno：系统调用错误码 */
#include <poll.h>         /* poll：I/O 多路复用，等待多个 fd 可读/可写 */
#include <pthread.h>      /* pthread：每个连接起一个线程 */
#include <string.h>
#include <unistd.h>       /* close/read/write 等 */

#include <openssl/ssl.h>  /* OpenSSL 核心：SSL_CTX / SSL 对象 */
#include <openssl/err.h>  /* OpenSSL 错误栈：ERR_error_string 等 */

#include <bpf/libbpf.h>   /* libbpf 用户态 API：加载/附加 BPF 程序 */
#include <bpf/bpf.h>      /* bpf() 系统调用封装：map 的增删查改 */

/* =====================================================================================
 * 第 1 部分：两侧共享的数据结构
 * -------------------------------------------------------------------------------------
 * 这些结构体必须在 BPF 侧和用户态侧保持【二进制布局一致】，否则写进 map 的数据
 * BPF 程序读出来就是乱的。实际项目中它们放在共享头文件里。
 * ===================================================================================== */

/*
 * shield_cfg：BPF 程序的"配置表"。
 * 用一个 ARRAY map（只有 1 个元素）来传配置，是 eBPF 编程的惯用手法：
 * 程序本身不能改（验证器禁止随意修改指令），但 map 内容随时可由用户态更新，
 * 于是"运行时可配置"就靠 map 实现了。
 */
struct shield_cfg {
	__u32 enabled;      /* 总开关：0 = BPF 程序全部放行，1 = 生效 */
	__u32 backend_ip4;  /* 后端真实地址（网络字节序），bind4 改写的目标 IP */
	__u16 protect_port; /* 受保护端口，即对外暴露的 9000（网络字节序） */
	__u16 proxy_port;   /* mtls_shield 自己监听的端口（redirect 模式用） */
	__u16 backend_port; /* 后端内部端口 19000（网络字节序），bind4 改写的目标端口 */
	__u16 reserved;     /* 占位，保证结构体 8 字节对齐，将来扩展用 */
};

/*
 * lpm_key：LPM（Longest Prefix Match，最长前缀匹配）trie 的 key。
 * 用来做"目标 IP 是否属于受保护网段"的判断，比如只对 10.0.0.0/8 生效。
 */
struct lpm_key {
	__u32 prefixlen; /* 前缀长度，32 表示精确匹配单个 IP */
	__u32 ip;        /* IP 地址（网络字节序） */
};

/* =====================================================================================
 * 第 2 部分：eBPF 程序（对应 src/mtls_shield.bpf.c）
 * -------------------------------------------------------------------------------------
 * 编译方式：clang -target bpf -O2 -c mtls_shield.bpf.c -o mtls_shield.bpf.o
 * 这段代码最终跑在内核态，受到 BPF 验证器的严格限制：
 *   - 不能调用普通 libc 函数（只能用 bpf_* 辅助函数）
 *   - 不能有无界循环
 *   - 每次内存访问都要先判空（验证器要能证明不会越界/空指针）
 * ===================================================================================== */

/*
 * BPF map 定义 1：配置表。
 *
 * 语法解读（libbpf 的 BTF-style map 定义）：
 *   __uint(type, BPF_MAP_TYPE_ARRAY)   -> map 类型是数组（key 必须是 0..max_entries-1）
 *   __uint(max_entries, 1)             -> 只有 1 个槽位，当配置表用
 *   __type(key, __u32)                 -> key 是 4 字节无符号整数
 *   __type(value, struct shield_cfg)   -> value 是配置结构体
 *   SEC(".maps")                       -> 放进 ELF 的 .maps 段，libbpf 加载时自动创建
 *
 * 为什么用 ARRAY 而不是 HASH？配置只有一条、key 恒为 0，ARRAY 没有哈希开销，
 * 且 ARRAY 的槽位永远存在（lookup 永不失败），代码更简单。
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct shield_cfg);
} shield_cfg_map SEC(".maps");

/*
 * BPF map 定义 2：受保护网段表（LPM trie）。
 *
 * LPM_TRIE 是专门为"IP 网段匹配"设计的数据结构，和路由表一样：
 * 查 key 10.1.2.3 时，如果表里有 10.0.0.0/8 和 10.1.0.0/16，会命中前缀最长的
 * 10.1.0.0/16。
 *
 * BPF_F_NO_PREALLOC：不预分配节点，插入时才分配。LPM 节点大小不定，必须用这个标志。
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, __u32);
} protect_nets SEC(".maps");

/*
 * BPF map 定义 3：SOCKMAP——存 socket 的 map（redirect 模式用）。
 *
 * 这是 eBPF 里最神奇的 map 之一：value 存的不是普通数据，而是一个
 * "struct bpf_sock *"（内核 socket 对象的引用）。sk_lookup 程序从这里取出
 * mtls_shield 的监听 socket，然后用 bpf_sk_assign() 把新连接"分派"给它。
 * 用户态只需把 listen_fd 写进 map，内核自动转换成 bpf_sock。
 */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} proxy_socks SEC(".maps");

/*
 * BPF map 定义 4：per-CPU 统计计数器。
 *
 * 为什么要 per-CPU？多个 CPU 同时跑这个程序时，普通 map 要靠锁/原子操作
 * 更新同一块内存，有性能损失。PERCPU_ARRAY 给每个 CPU 一份独立副本，
 * 写的时候完全无锁；读的时候（用户态）把各 CPU 的值加起来即可。
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

/* 统计项的下标，和 map 的 key 一一对应 */
enum stat_key {
	STAT_SK_REDIRECT = 0,   /* sk_lookup 成功改派连接的次数 */
	STAT_CONNECT_REDIRECT,  /* connect4 改写的次数 */
	STAT_NO_SOCKET,         /* SOCKMAP 里没有代理 socket 的异常次数 */
	STAT_ASSIGN_ERROR,      /* bpf_sk_assign 失败次数 */
	STAT_SEEN,              /* sk_lookup 被触发的总次数（调试用） */
	STAT_PORT_MATCH,        /* 端口命中受保护端口的次数 */
	STAT_BIND_REDIRECT,     /* bind4 改写成功的次数——同端口模式的核心指标 */
};

/*
 * 统计自增。
 *
 * __always_inline 强制内联：BPF 里函数调用会消耗栈和指令数，小工具函数都内联。
 *
 * __sync_fetch_and_add(value, 1)：GCC 原子自增。虽然 PERCPU_ARRAY 理论上无竞争，
 * 但同一 CPU 上也可能有中断/软中断重入（比如处理网络包时又被打断），所以仍用原子操作。
 */
static __always_inline void stat_inc(__u32 key)
{
	__u64 *value = bpf_map_lookup_elem(&stats, &key);

	if (value) /* 验证器要求：lookup 结果必须判空后才能解引用 */
		__sync_fetch_and_add(value, 1);
}

/*
 * 判断某个 IP 是否在受保护网段内。
 *
 * 查询技巧：prefixlen=32 表示"拿这个 IP 当完整 32 位前缀去查"。
 * LPM trie 会自动做最长前缀匹配：IP 10.1.2.3 能命中表里的 10.0.0.0/8。
 * 查到（返回非空）就说明受保护。
 */
static __always_inline int net_is_protected(__u32 ip)
{
	struct lpm_key key = {
		.prefixlen = 32,
		.ip = ip,
	};

	return bpf_map_lookup_elem(&protect_nets, &key) != 0;
}

/*
 * =====================================================================================
 * 程序 1：SEC("sk_lookup") —— 入站连接劫持（redirect 模式用）
 * -------------------------------------------------------------------------------------
 * 挂载点：网络命名空间（netns）。当一个 TCP 包到达、内核要为它找"归宿 socket"
 * （即四元组匹配监听 socket）时，先执行这个程序。
 *
 * 用途：客户端连 9000，但 mtls_shield 可能监听在别的端口（redirect 模式）。
 * 这个程序用 bpf_sk_assign() 把这个连接强制"递给" SOCKMAP 里的代理 socket，
 * 于是客户端完全无感知——它以为自己连的是 9000 上的服务。
 *
 * 注意：同端口模式（默认）不需要这个程序，只用下面的 bind4。
 * =====================================================================================
 */
SEC("sk_lookup")
int shield_sk_lookup(struct bpf_sk_lookup *ctx)
{
	__u32 zero = 0;           /* ARRAY map 的 key 恒为 0 */
	struct shield_cfg *cfg;
	struct bpf_sock *sk;
	__u32 sock_key = 0;
	long ret;

	stat_inc(STAT_SEEN);      /* 先记一笔"程序被触发"，方便调试 */

	/* 从配置 map 读配置。注意：BPF 里所有 map 查询都返回指针或 NULL */
	cfg = bpf_map_lookup_elem(&shield_cfg_map, &zero);
	if (!cfg)
		return SK_PASS;   /* 没配置就放行。SK_PASS = 正常走内核 socket 匹配 */

	/* 只处理 IPv4 + TCP，其余协议不碰 */
	if (ctx->family != AF_INET || ctx->protocol != IPPROTO_TCP)
		return SK_PASS;

	/*
	 * 端口比较的字节序陷阱：
	 * ctx->local_port 是【主机字节序】的 u16；
	 * cfg->protect_port 存的是【网络字节序】（用户态写入时 htons 过）。
	 * 所以这里用 bpf_ntohs 把配置转回主机序再比较。
	 * （先转 u16 再比较，避免 u32 高位垃圾干扰）
	 */
	if (!cfg->enabled ||
	    (__u16)ctx->local_port != bpf_ntohs(cfg->protect_port))
		return SK_PASS;

	stat_inc(STAT_PORT_MATCH);

	/* 目标 IP 不在受保护网段内（比如 --protect-net 限定了范围）就放行 */
	if (!net_is_protected(ctx->local_ip4))
		return SK_PASS;

	/* 从 SOCKMAP 取出代理 socket（用户态在启动时写入的 listen_fd） */
	sk = bpf_map_lookup_elem(&proxy_socks, &sock_key);
	if (!sk) {
		stat_inc(STAT_NO_SOCKET);
		return SK_PASS;
	}

	/*
	 * bpf_sk_assign：把找到的 socket 指派给当前待分派的连接。
	 * 这是 sk_lookup 程序存在的全部意义——它能改写"内核给这个连接选谁来收"。
	 * 参数 0 是 flags，目前必须为 0。
	 */
	ret = bpf_sk_assign(ctx, sk, 0);

	/*
	 * bpf_sk_release：释放 lookup 拿到的 socket 引用。
	 * BPF 的引用计数规则：bpf_map_lookup_elem 对 SOCKMAP 返回的 sk 是"引用"，
	 * 用完必须 bpf_sk_release，否则内核对象泄漏。这是验证器强制检查的。
	 */
	bpf_sk_release(sk);
	if (ret) {
		stat_inc(STAT_ASSIGN_ERROR);
		return SK_PASS;
	}

	stat_inc(STAT_SK_REDIRECT);
	return SK_PASS; /* 即使改派成功也返回 SK_PASS：包照常送进（改派后的）socket */
}

/*
 * =====================================================================================
 * 程序 2：SEC("cgroup/bind4") —— 本项目的核心！透明改写后端的 bind()
 * -------------------------------------------------------------------------------------
 * 挂载点：cgroup（这里用 /sys/fs/cgroup 根 cgroup）。任何进程在该 cgroup 里
 * 调用 bind(2) 绑 IPv4 地址时，内核都会先执行这个程序。
 *
 * 工作原理：ctx 是 struct bpf_sock_addr *，它就是【内核里正准备使用的
 * sockaddr】。程序直接改写 ctx->user_ip4 / ctx->user_port，改完之后内核
 * 继续执行 bind 流程——于是进程以为自己绑定了 9000，实际绑定了 19000。
 *
 * 返回值约定（cgroup/bind4）：
 *   1 = 允许（继续执行 bind）
 *   0 = 拒绝（bind 直接返回 EACCES/EPERM 类错误）
 * 注意和 sk_lookup 的 SK_PASS/SK_DROP 不同！
 * =====================================================================================
 */
SEC("cgroup/bind4")
int shield_bind4(struct bpf_sock_addr *ctx)
{
	__u32 zero = 0;
	struct shield_cfg *cfg;

	cfg = bpf_map_lookup_elem(&shield_cfg_map, &zero);

	/* 未启用、或没配后端端口 -> 不干预，让 bind 正常执行 */
	if (!cfg || !cfg->enabled || !cfg->backend_port)
		return 1;

	/*
	 * 关键比较：ctx->user_port 是【网络字节序】的 __be16（bind 语义里
	 * sockaddr 的端口本来就是网络序），所以直接和配置比，不需要转换。
	 * 这和 sk_lookup 里 ctx->local_port（主机序）的处理不同，务必注意！
	 *
	 * 只有绑定了"受保护端口 9000"的 bind 才改写；其他端口（比如调试端口、
	 * metrics 端口）一律不碰。
	 */
	if ((__u16)ctx->user_port != cfg->protect_port)
		return 1;

	/* --- 核心动刀：原地改写 sockaddr --- */
	ctx->user_port = cfg->backend_port;   /* 9000 -> 19000 */
	if (cfg->backend_ip4)                 /* 如果配置了目标 IP（通常 127.0.0.1） */
		ctx->user_ip4 = cfg->backend_ip4; /* 把绑定地址也限定到回环，防外部直连明文后端 */

	stat_inc(STAT_BIND_REDIRECT);

	/*
	 * 仍然返回 1（放行）！我们不是要拒绝 bind，而是"改完参数后让它成功"。
	 * 内核接着用改写后的 {127.0.0.1, 19000} 去做真正的绑定。
	 *
	 * 副作用提示（README 里也写了）：后端调用 getsockname() 会看到 19000。
	 * 如果后端把端口号写进业务响应或做自连接，会露出内部端口。
	 */
	return 1;
}

/*
 * =====================================================================================
 * 程序 3：SEC("cgroup/connect4") —— 本机出站连接改写（redirect 模式补充）
 * -------------------------------------------------------------------------------------
 * 场景：redirect 模式下，如果客户端和服务跑在同一台机器，客户端 connect(9000)
 * 会命中本机回环直达。sk_lookup 对"本机发出的连接"不一定被触发（取决于内核
 * 路径），所以在 connect(2) 系统调用层把目标端口改写成代理端口，双保险。
 *
 * 同端口模式（默认）不使用它。
 * =====================================================================================
 */
SEC("cgroup/connect4")
int shield_connect4(struct bpf_sock_addr *ctx)
{
	__u32 zero = 0;
	struct shield_cfg *cfg;

	cfg = bpf_map_lookup_elem(&shield_cfg_map, &zero);
	if (!cfg)
		return 1;
	if (!cfg->enabled || (__u16)ctx->user_port != cfg->protect_port)
		return 1;
	if (!net_is_protected(ctx->user_ip4))
		return 1;

	/* 把 connect 的目标端口 9000 改写成代理监听端口 */
	ctx->user_port = cfg->proxy_port;
	stat_inc(STAT_CONNECT_REDIRECT);
	return 1; /* 放行，但目标已改 */
}

/*
 * BPF 程序的 license 声明。
 * 必须是 GPL 兼容（GPL/GPL2/BSD 等），否则内核拒绝加载——因为很多 bpf_ 辅助
 * 函数（如 bpf_sk_assign 所在的 GPL-only 区）只对 GPL 程序开放。
 * 这行不能删，删了程序直接加载失败。
 */
char LICENSE[] SEC("license") = "GPL";

/* =====================================================================================
 * 第 3 部分：用户态代理（对应 src/mtls_shield.c 的核心流程）
 * ===================================================================================== */

/* ---------- 3.0 全局配置与状态 ---------- */

#define RELAY_BUF_SIZE 65536 /* 转发缓冲区 64KB，一次 read/write 的上限 */

/*
 * 后端地址（预先解析成 sockaddr_in，转发时直接 connect，省得每个连接重复解析域名）
 */
static struct sockaddr_in g_upstream_addr;

/* OpenSSL 的 SSL_CTX：全局一个，所有连接的 SSL 对象都从它派生（证书/校验策略共享） */
static SSL_CTX *g_tls_ctx;

/*
 * libbpf skeleton 句柄。
 * skeleton 是 bpftool 从 mtls_shield.bpf.o 自动生成的 C 头文件（mtls_shield.skel.h），
 * 它把 BPF 程序和 map 包装成 C 结构体，用法变成：
 *   g_skel->maps.shield_cfg_map   -> 直接拿到 map 指针
 *   g_skel->progs.shield_bind4    -> 直接拿到 program 指针
 * 不用再手工按名字去 bpf_object__find_map_by_name 了。
 */
static struct mtls_shield_bpf *g_skel;

/* bpf_link：程序"挂载"的句柄，持有它才能在退出时解除挂载（detach） */
static struct bpf_link *g_sk_link;   /* sk_lookup 挂载句柄 */
static struct bpf_link *g_cg_link;   /* connect4 挂载句柄 */
static struct bpf_link *g_bind_link; /* bind4 挂载句柄 */

/* 同端口模式标志：listen 端口 == protect 端口时启用（默认模式） */
static int g_same_port;

/*
 * 信号处理：用 volatile sig_atomic_t 保证异步信号安全。
 * SIGINT/SIGTERM -> g_stop = 1 通知主循环退出；
 * SIGUSR1 -> g_want_stats = 1 请求打印统计。
 */
static volatile sig_atomic_t g_stop;

/* ---------- 3.1 OpenSSL 初始化：构造 mTLS 服务端 ---------- */

/*
 * 证书 CN 提取：从 X509 证书的 Subject 里取 commonName。
 * ASN1_STRING_to_UTF8 把内部编码统一转成 UTF-8（CN 可能是各种字符集）。
 * 调用者负责 OPENSSL_free(utf8)。
 */
static int cert_common_name(X509 *cert, char *buf, size_t buflen);

/*
 * mTLS 的核心回调：客户端证书校验函数。
 *
 * OpenSSL 的校验流程：握手时收到客户端证书链后，逐级验证（自签名根 -> 中间CA ->
 * 叶子证书），每验证一级就调用一次本回调。
 *
 * 参数 preverify_ok：
 *   1 = 本级证书链验证已通过（签名有效、在有效期内、能链到信任的 CA）
 *   0 = 本级验证失败（不受信的 CA、过期、吊销等）
 *
 * 参数 store：证书验证上下文，可查询当前验证到哪级证书、错误原因。
 *
 * 返回值：1 = 接受，0 = 拒绝（握手失败，连接断开）。
 *
 * 本项目的两层防线：
 *   第一层（默认）：preverify_ok 必须为 1，即客户端证书必须链到 --ca 指定的 CA。
 *   第二层（可选 --allow-cn）：只对 depth==0（叶子证书，即客户端本人）检查 CN 白名单。
 *   depth > 0 的是 CA 证书，不参与 CN 检查（CA 的 CN 无所谓）。
 */
static int verify_client_cert(int preverify_ok, X509_STORE_CTX *store)
{
	X509 *cert;
	char cn[256];
	int depth;

	/* X509_STORE_CTX_get_error_depth：当前验证到证书链的第几级，0 = 叶子（客户端自身） */
	depth = X509_STORE_CTX_get_error_depth(store);

	if (!preverify_ok) {
		/* ---- 第一层防线：证书链验证失败，直接拒绝 ---- */
		cert = X509_STORE_CTX_get_current_cert(store);
		cn[0] = '\0';
		if (cert)
			cert_common_name(cert, cn, sizeof(cn));
		/*
		 * X509_verify_cert_error_string：把错误码翻译成人话，
		 * 比如 "unable to get local issuer certificate"（客户端没带 CA 签的证）
		 * 或 "certificate has expired"。
		 */
		log_error("client certificate rejected at depth %d (cn=%s): %s",
			  depth, cn[0] ? cn : "-",
			  X509_verify_cert_error_string(
				  X509_STORE_CTX_get_error(store)));
		return 0; /* 拒绝 -> 握手失败 */
	}

	/* ---- 第二层防线：CN 白名单（没配置就直接放行） ---- */
	if (depth != 0 || g_allow_cn_count == 0)
		return 1; /* 中间/根 CA 证书不检查 CN；没配白名单则只靠第一层 */

	cert = X509_STORE_CTX_get_current_cert(store);
	if (!cert || cert_common_name(cert, cn, sizeof(cn)) != 0) {
		log_error("client certificate has no usable common name");
		return 0;
	}

	for (int i = 0; i < g_allow_cn_count; i++) {
		/* strcmp 精确匹配：注意大小写敏感，配置时要和证书 CN 完全一致 */
		if (strcmp(cn, g_allow_cns[i]) == 0)
			return 1;
	}

	log_error("client certificate cn=%s is not in --allow-cn list", cn);
	return 0;
}

static int tls_init(void)
{
	/*
	 * OPENSSL_init_ssl：初始化 OpenSSL（1.1.0+ 可省略，但显式调用更规范；
	 * 旧版本必须调用，否则 SSL_library_init/SSL_load_error_strings 缺失会崩）。
	 */
	OPENSSL_init_ssl(0, NULL);

	/*
	 * TLS_server_method()：创建"服务端"模式的 SSL_CTX。
	 * OpenSSL 1.1.0+ 用 method 区分客户端/服务端/DTLS 等；
	 * 旧式写法是 SSLv23_server_method()。
	 */
	g_tls_ctx = SSL_CTX_new(TLS_server_method());
	if (!g_tls_ctx) {
		log_error("SSL_CTX_new failed: %s", ssl_error_string());
		return -1;
	}

	/*
	 * 强制 TLS 1.2 起步：SSL_CTX_set_min_proto_version 禁用 SSLv3/TLS1.0/1.1
	 * （这些老版本有 BEAST/POODLE 等已知攻击）。
	 */
	if (!SSL_CTX_set_min_proto_version(g_tls_ctx, TLS1_2_VERSION)) {
		log_error("failed to set minimum TLS version");
		return -1;
	}

	/* SSL_OP_NO_COMPRESSION：禁用 TLS 压缩，防 CRIME/BREACH 压缩侧信道攻击 */
	SSL_CTX_set_options(g_tls_ctx, SSL_OP_NO_COMPRESSION);

	/*
	 * 两个常用 mode：
	 *   ENABLE_PARTIAL_WRITE：SSL_write 允许只写一部分（剩下的下次接着写），
	 *     转发代理必须开，否则一次没写完就报错。
	 *   ACCEPT_MOVING_WRITE_BUFFER：允许下次 SSL_write 用不同的缓冲区地址。
	 *     轮询转发里写缓冲位置会滑动，不开会触发 "bad write retry"。
	 */
	SSL_CTX_set_mode(g_tls_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
				   SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	/* 加载服务端证书链（.crt 文件里可以是"叶子证书 + 中间 CA"多段 PEM） */
	if (!SSL_CTX_use_certificate_chain_file(g_tls_ctx, g_cfg.cert_file)) {
		log_error("cannot load server certificate %s: %s",
			  g_cfg.cert_file, ssl_error_string());
		return -1;
	}
	/* 加载服务端私钥（PEM 格式）。私钥绝不能打进日志——这是红线 */
	if (!SSL_CTX_use_PrivateKey_file(g_tls_ctx, g_cfg.key_file,
					 SSL_FILETYPE_PEM)) {
		log_error("cannot load private key %s: %s", g_cfg.key_file,
			  ssl_error_string());
		return -1;
	}
	/*
	 * check_private_key：校验证书和私钥是否配对（公钥对不上就说明配错了文件）。
	 * 这步不做的话，握手时才会报错，问题更难排查。
	 */
	if (!SSL_CTX_check_private_key(g_tls_ctx)) {
		log_error("server certificate and key do not match");
		return -1;
	}

	/*
	 * 加载"信任的客户端 CA"——mTLS 的信任根。
	 * 客户端握手时必须出示由此 CA 签发的证书，否则第一层校验直接失败。
	 */
	if (!SSL_CTX_load_verify_locations(g_tls_ctx, g_cfg.ca_file, NULL)) {
		log_error("cannot load client CA %s: %s", g_cfg.ca_file,
			  ssl_error_string());
		return -1;
	}

	/*
	 * SSL_load_client_CA_file + SSL_CTX_set_client_CA_list：
	 * 把 CA 的 Subject 名字列表发给客户端（CertificateRequest 报文里的
	 * certificate_authorities 字段），客户端据此挑一张合适的证书。
	 * 不设的话客户端可能不知道该出示哪张证书。
	 */
	ca_names = SSL_load_client_CA_file(g_cfg.ca_file);
	if (!ca_names) {
		log_error("cannot build client CA list from %s", g_cfg.ca_file);
		return -1;
	}
	SSL_CTX_set_client_CA_list(g_tls_ctx, ca_names);

	/*
	 * ★ mTLS 的灵魂一行 ★
	 *   SSL_VERIFY_PEER               -> 要求并验证对端证书（单向 TLS 时服务端不校验客户端）
	 *   SSL_VERIFY_FAIL_IF_NO_PEER_CERT -> 客户端不给证书就直接失败（否则匿名客户端能混进来）
	 * 第三个参数是自定义回调 verify_client_cert，做上面说的两层校验。
	 *
	 * 对比：普通 HTTPS 只设 SSL_VERIFY_NONE（服务端不验客户端），那就是单向 TLS。
	 */
	SSL_CTX_set_verify(g_tls_ctx,
			   SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			   verify_client_cert);

	return 0;
}

/* ---------- 3.2 监听 socket：占据对外端口 9000 ---------- */

static int create_listener(void)
{
	struct sockaddr_in addr;
	int fd;
	int one = 1;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	/*
	 * SOCK_CLOEXEC：exec 时自动关闭此 fd。防止 mtls_shield 调用外部程序
	 * （比如将来扩展）时把监听 socket 泄漏给子进程。
	 */
	if (fd < 0) {
		log_error("socket: %s", strerror(errno));
		return -1;
	}

	/*
	 * SO_REUSEADDR：允许绑定处于 TIME_WAIT 状态的端口，重启时不用等 2MSL。
	 * 注意：它【不】允许两个进程同时绑定同一 IP:Port（那是 SO_REUSEPORT），
	 * 所以后端和 mtls_shield 仍然冲突——这正是需要 eBPF 的原因。
	 */
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(g_cfg.listen.port); /* 主机序 -> 网络序，bind 的硬性要求 */
	inet_pton(AF_INET, g_cfg.listen.host, &addr.sin_addr);
	/* inet_pton：把 "0.0.0.0" 这样的字符串转成网络序二进制 IP */

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		/*
		 * 同端口模式下如果报 EADDRINUSE，几乎一定是启动顺序错了：
		 * 后端先启动并成功 bind 了 9000（此时 eBPF 还没挂上，没被改写），
		 * 轮到 mtls_shield 时端口已被占。正确顺序：先起 mtls_shield，再起后端。
		 */
		log_error("bind %s:%d: %s", g_cfg.listen.host,
			  g_cfg.listen.port, strerror(errno));
		if (g_same_port && errno == EADDRINUSE)
			log_error("start mtls_shield before the backend ...");
		close(fd);
		return -1;
	}

	/* listen(fd, 256)：backlog=256，即已完成握手等待 accept 的队列长度 */
	if (listen(fd, 256) < 0) {
		log_error("listen: %s", strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

/* ---------- 3.3 连接后端：非阻塞 connect 的标准写法 ---------- */

/*
 * connect_upstream：连接 127.0.0.1:19000 的后端。
 *
 * 这里演示了一个经典模式【非阻塞 connect + poll 等待】：
 *   1. set_nonblocking(fd) 设为非阻塞；
 *   2. connect() 对非阻塞 socket 几乎总是立刻返回 -1/EINPROGRESS
 *      （TCP 三次握手还没完成，但内核已发起 SYN）；
 *   3. poll(POLLOUT) 等到可写 = 握手完成（或失败）；
 *   4. getsockopt(SO_ERROR) 取真正的连接结果（0 = 成功，其他是 errno）。
 *
 * 为什么要非阻塞？因为整个 connect 可能耗时很久（对方不可达要等超时），
 * 用 poll 带 5 秒超时，比阻塞 connect（默认可能等 2 分钟）可控得多。
 */
static int connect_upstream(void)
{
	struct pollfd pfd;
	int fd;
	int err = 0;
	socklen_t errlen = sizeof(err);
	int one = 1;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	/*
	 * TCP_NODELAY：禁用 Nagle 算法，小包立即发出。
	 * 代理场景必须开：TLS 记录本身已经是聚合过的数据块，再让 Nagle 缓存
	 * 会平白增加延迟（交互式协议如 Redis/HTTP 短请求对延迟敏感）。
	 */
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	if (set_nonblocking(fd) < 0) {
		close(fd);
		return -1;
	}

	if (connect(fd, (struct sockaddr *)&g_upstream_addr,
		    sizeof(g_upstream_addr)) < 0) {
		if (errno != EINPROGRESS) { /* 真错了（比如路由不可达立即报错） */
			close(fd);
			return -1;
		}
		pfd.fd = fd;
		pfd.events = POLLOUT; /* 等待"可写"= 连接建立完成 */
		pfd.revents = 0;
		{
			int pr = poll(&pfd, 1, 5000); /* 最多等 5 秒 */

			if (pr <= 0) {
				if (pr == 0)          /* 超时 */
					errno = ETIMEDOUT;
				close(fd);
				return -1;
			}
		}
		/*
		 * poll 说可写后，必须用 SO_ERROR 确认连接真的成功了：
		 * 连接失败时 socket 也是"可写"的（可写 + SO_ERROR != 0 表示失败）。
		 * 这是非阻塞 connect 最容易写错的一步。
		 */
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0) {
			close(fd);
			return -1;
		}
		if (err != 0) {
			errno = err;
			close(fd);
			return -1;
		}
	}

	return fd;
}

/* ---------- 3.4 双向转发：poll 驱动的 relay 主循环 ---------- */

/*
 * relay_loop：在【TLS 客户端】和【明文后端】之间搬运数据。
 *
 * 两个方向：
 *   客户端 -> 后端：SSL_read（解密）-> write(ufd)
 *   后端 -> 客户端：read(ufd) -> SSL_write（加密）
 *
 * 难点在于：read/SSL_read/SSL_write 都是"部分完成"友好的——
 *   - read 可能只读到一半；
 *   - SSL_write 可能只写出一半（因为开了 PARTIAL_WRITE）；
 *   - SSL_read 可能因 TLS 缓冲而返回 WANT_WRITE/WANT_READ（非阻塞下）。
 * 所以每个方向都要维护 [buf, off, len] 三元组：off 之前是已消费，off..len 是待发。
 *
 * 还要正确处理 TCP 半关闭（shutdown(SHUT_WR)）：
 *   客户端发完请求后 shutdown 写端（HTTP 短连接常见），后端还在回数据——
 *   这时不能把整个连接掐掉，要继续把后端数据传完。
 */
static int relay_loop(SSL *ssl, int cfd, int ufd)
{
	/* 两个方向各一个 64KB 环形用缓冲（这里用"平移式"缓冲，更简单） */
	unsigned char *to_up = malloc(RELAY_BUF_SIZE);   /* 客户端 -> 后端 */
	unsigned char *to_cli = malloc(RELAY_BUF_SIZE);  /* 后端 -> 客户端 */
	size_t up_off = 0, up_len = 0;   /* 待发往后端的数据窗口 */
	size_t cli_off = 0, cli_len = 0; /* 待发往客户端的数据窗口 */
	int client_eof = 0;   /* 客户端读到 EOF（对方 shutdown 写端或断开） */
	int upstream_eof = 0; /* 后端读到 EOF */
	int upstream_shut = 0; /* 已对后端执行 shutdown(SHUT_WR) */
	int rc = 0;

	for (;;) {
		struct pollfd pfds[2];
		short cev = 0, uev = 0; /* 各自要等待的事件 */

		if (g_stop) { rc = 0; break; } /* 收到 SIGINT/TERM，优雅退出 */

		/*
		 * 构造 poll 事件——注意"有数据待发时才注册 POLLOUT"，
		 * 否则 socket 一直可写，poll 会 100% CPU 空转（经典 bug）。
		 */
		cev = POLLIN;
		if (client_want_write || cli_len > 0)
			cev |= POLLOUT;
		uev = POLLIN;
		if (up_len > 0)
			uev |= POLLOUT;

		pfds[0].fd = cfd;
		pfds[0].events = cev;
		pfds[1].fd = ufd;
		pfds[1].events = uev;

		/* poll(-1) 无限等；生产代码一般给个 60s 超时做兜底 */
		if (poll(pfds, 2, -1) < 0) {
			if (errno == EINTR) continue; /* 被信号打断，重试 */
			rc = -1;
			break;
		}

		/* ---- 处理客户端方向 ---- */
		if (pfds[0].revents & (POLLIN | POLLHUP)) {
			/*
			 * SSL_read：从 TLS 连接读【明文】。
			 * 返回 >0 = 读到 n 字节明文；=0 = TLS 正常关闭（close_notify）；
			 * <0 = 出错或需要重试（SSL_get_error 区分）。
			 */
			int n = SSL_read(ssl, to_up + up_len, RELAY_BUF_SIZE - up_len);
			if (n > 0) {
				up_len += n; /* 累积待发数据 */
			} else if (n == 0) {
				client_eof = 1; /* TLS 层正常结束 */
			} else {
				/* 简化：真实实现要处理 SSL_ERROR_WANT_READ/WRITE */
				client_eof = 1;
			}
		}

		/* ---- 处理后端方向（对称逻辑，用普通 read）---- */
		if (pfds[1].revents & (POLLIN | POLLHUP)) {
			int n = read(ufd, to_cli + cli_len, RELAY_BUF_SIZE - cli_len);
			if (n > 0)
				cli_len += n;
			else if (n == 0)
				upstream_eof = 1; /* 后端发完 FIN */
			else {
				rc = -1;
				break;
			}
		}

		/* ---- 冲刷待发缓冲 ---- */
		if (up_len > 0 && (pfds[1].revents & POLLOUT)) {
			ssize_t n = write(ufd, to_up + up_off, up_len - up_off);
			if (n > 0) {
				up_off += n;
				if (up_off == up_len) /* 发完了，窗口归零 */
					up_off = up_len = 0;
			}
		}
		if (cli_len > 0 && (pfds[0].revents & POLLOUT)) {
			int n = SSL_write(ssl, to_cli + cli_off, cli_len - cli_off);
			if (n > 0) {
				cli_off += n;
				if (cli_off == cli_len)
					cli_off = cli_len = 0;
			}
		}

		/*
		 * 半关闭处理：客户端读尽且待发数据已全部转交后端 ->
		 * 告诉后端"客户端不会再发了"（shutdown 写端），
		 * 后端处理完会自己发 FIN，连接才能干净地走完。
		 */
		if (client_eof && up_len == 0 && !upstream_shut) {
			shutdown(ufd, SHUT_WR);
			upstream_shut = 1;
		}

		/* 双向都收尾，正常退出 */
		if (client_eof && upstream_eof &&
		    up_len == 0 && cli_len == 0)
			break;
		/* 一端断了且缓冲已清空，也该收工（对端会自己收 EOF） */
		if ((client_eof && cli_len == 0) ||
		    (upstream_eof && up_len == 0))
			break;
	}

	free(to_up);
	free(to_cli);
	return rc;
}

/* ---------- 3.5 每连接一个线程 ---------- */

/*
 * conn_thread：单个客户端连接的处理入口（pthread 启动函数）。
 *
 * 流程：
 *   accept 出来的 fd -> SSL_new/SSL_set_fd -> SSL_accept（mTLS 握手，含验客户端证书）
 *   -> connect_upstream 连后端 -> relay_loop 转发 -> 清理退出。
 *
 * 线程模型评价：每连接一线程实现简单、延迟可控，适合演示和中小流量；
 * 高并发（>1k 连接）应改 epoll 事件驱动 + 线程池/协程，避免线程栈开销和
 * 上下文切换。README 的"限制"一节也如实写了这点。
 */
static void *conn_thread(void *opaque)
{
	struct conn_arg *arg = opaque;
	int cfd = arg->fd;
	int ufd = -1;
	SSL *ssl = NULL;

	/* SSL_new：从全局 SSL_CTX 派生一个连接级 SSL 对象（每个连接独立） */
	ssl = SSL_new(g_tls_ctx);
	if (!ssl)
		goto out;

	/* SSL_set_fd：把 SSL 对象绑定到已 accept 的 socket 上 */
	SSL_set_fd(ssl, cfd);

	/*
	 * SSL_accept：执行服务端握手。
	 * mTLS 的关键动作都发生在这里：
	 *   - 服务端发自己的证书（由 SSL_CTX 决定）
	 *   - 服务端发 CertificateRequest（因为设了 SSL_VERIFY_PEER）
	 *   - 客户端回证书 -> 触发 verify_client_cert 回调链
	 *   - 任何一层校验失败 -> SSL_accept 返回 <=0，连接作废
	 * 明文客户端（比如 telnet/curl 不带证书）走到这里必然失败——这就是
	 * "明文客户端无法绕过 mTLS"的原理。
	 */
	if (SSL_accept(ssl) <= 0) {
		log_error("TLS handshake failed from %s", arg->peer_str);
		goto out;
	}

	/* 握手成功后可以取客户端证书信息做审计日志（只记 CN，不记私钥/数据） */
	{
		X509 *peer = SSL_get_peer_certificate(ssl);
		if (peer) {
			char cn[256];
			if (cert_common_name(peer, cn, sizeof(cn)) == 0)
				log_info("client connected: %s (cn=%s)",
					 arg->peer_str, cn);
			X509_free(peer); /* SSL_get_peer_certificate 返回的是引用，必须释放 */
		}
	}

	/* 连后端（127.0.0.1:19000） */
	ufd = connect_upstream();
	if (ufd < 0) {
		log_error("cannot connect upstream from %s", arg->peer_str);
		goto out;
	}

	/* 双向转发，直到任一方向结束 */
	relay_loop(ssl, cfd, ufd);

out:
	/* 清理顺序很重要：先 SSL_shutdown（发 close_notify），再 free，最后 close fd */
	if (ssl) {
		SSL_shutdown(ssl); /* 尽力而为，非阻塞下可能没发完，无所谓 */
		SSL_free(ssl);
	}
	if (ufd >= 0)
		close(ufd);
	close(cfd);
	free(arg);
	__sync_fetch_and_sub(&g_active_conns, 1);
	return NULL;
}

/* ---------- 3.6 accept 主循环 ---------- */

static void accept_loop(int listen_fd)
{
	while (!g_stop) {
		struct conn_arg *arg;
		struct sockaddr_storage peer;
		socklen_t peer_len = sizeof(peer);
		pthread_t tid;
		int fd;

		/*
		 * accept 会被信号中断（EINTR），必须重试，否则一个 SIGUSR1
		 * （打印统计）就可能让整个代理退出循环。
		 */
		fd = accept(listen_fd, (struct sockaddr *)&peer, &peer_len);
		if (fd < 0) {
			if (errno == EINTR)
				continue;
			if (g_stop)
				break;
			log_error("accept: %s", strerror(errno));
			continue;
		}

		/* 并发保护：超过 max_conns 直接拒绝，防止线程数无限膨胀拖垮机器 */
		if (__sync_fetch_and_add(&g_active_conns, 1) >= g_cfg.max_conns) {
			__sync_fetch_and_sub(&g_active_conns, 1);
			close(fd);
			continue;
		}

		arg = malloc(sizeof(*arg));
		if (!arg) {
			__sync_fetch_and_sub(&g_active_conns, 1);
			close(fd);
			continue;
		}
		arg->fd = fd;
		arg->peer = peer;
		arg->peer_len = peer_len;
		format_addr(&peer, peer_len, arg->peer_str, sizeof(arg->peer_str));

		/*
		 * pthread_create + pthread_detach：
		 * detach 后线程结束自动回收资源，不用主线程 pthread_join。
		 * 主循环只管 accept，绝不阻塞在某个连接上。
		 */
		if (pthread_create(&tid, NULL, conn_thread, arg) != 0) {
			log_error("pthread_create failed");
			__sync_fetch_and_sub(&g_active_conns, 1);
			close(fd);
			free(arg);
			continue;
		}
		pthread_detach(tid);
	}
}

/* ---------- 3.7 eBPF 装载与挂载 ---------- */

/*
 * attach_cgroup_prog：把 BPF 程序挂到指定 cgroup。
 *
 * 流程：open(cgroup 目录) -> bpf_program__attach_cgroup -> close(dirfd)。
 * 注意 close 之后 link 依然有效：attach 时内核持有的是 cgroup 的引用，
 * 而不是 fd。fd 只是"告诉内核挂到哪"的一次性门票。
 */
static struct bpf_link *attach_cgroup_prog(struct bpf_program *prog,
					   const char *path)
{
	struct bpf_link *link;
	int fd;

	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	link = bpf_program__attach_cgroup(prog, fd);
	close(fd);
	return link;
}

static int bpf_setup(int listen_fd)
{
	struct shield_cfg cfg;
	uint32_t key = 0;

	/*
	 * libbpf skeleton 三部曲：
	 *   1. __open()   —— 解析 ELF，创建 map/program 对象（还没进内核）
	 *   2. __load()   —— 把程序和 map 装进内核（经过验证器严格检查）
	 *   3. __attach() —— 挂到挂载点（这里是手动 attach 到 cgroup/netns）
	 * 这个三段式允许在 load 之后、attach 之前修改 map（比如写配置），
	 * 因为 map 在 load 时就已创建好，attach 只是"开始生效"。
	 */
	g_skel = mtls_shield_bpf__open();
	if (!g_skel) {
		log_error("cannot open BPF skeleton: %s", strerror(errno));
		return -1;
	}
	if (mtls_shield_bpf__load(g_skel)) {
		log_error("cannot load BPF programs: %s", strerror(errno));
		return -1;
	}

	/* --- 填写配置 map（BPF 程序运行时读的就是这份）--- */
	memset(&cfg, 0, sizeof(cfg));
	cfg.enabled = 1;
	cfg.protect_port = htons((uint16_t)g_cfg.protect_port); /* 必须转网络序！ */
	cfg.proxy_port = htons((uint16_t)g_cfg.listen.port);
	if (g_same_port) {
		/* 同端口模式：bind4 的改写目标 */
		cfg.backend_ip4 = g_upstream_addr.sin_addr.s_addr; /* 已是网络序 */
		cfg.backend_port = htons((uint16_t)g_cfg.upstream.port);
	}

	/*
	 * bpf_map__fd -> bpf_map_update_elem：
	 * 用户态往 map 写数据用 bpf() 系统调用的 BPF_MAP_UPDATE_ELEM 命令。
	 * BPF_ANY = "存在则覆盖，不存在则插入"。
	 * key=0 是 ARRAY map 唯一的槽位。
	 */
	map_fd = bpf_map__fd(g_skel->maps.shield_cfg_map);
	if (map_fd < 0 ||
	    bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY) != 0) {
		log_error("cannot write shield config map: %s", strerror(errno));
		return -1;
	}

	if (g_same_port) {
		/*
		 * 同端口模式只需要挂 bind4 一个程序！
		 * 挂到 /sys/fs/cgroup 根 cgroup —— 意味着【系统上所有进程】的 bind
		 * 都会过这个程序（好在逻辑只改写 protect_port，其他一律放行）。
		 * 生产环境更严谨的做法：为后端进程建独立 cgroup，只挂到那里。
		 */
		g_bind_link = attach_cgroup_prog(g_skel->progs.shield_bind4,
						 "/sys/fs/cgroup");
		if (!g_bind_link) {
			log_error("cannot attach cgroup/bind4: %s",
				  strerror(errno));
			return -1;
		}
		log_info("attached cgroup/bind4; backend binds to tcp/%d "
			 "will be moved to %s:%d",
			 g_cfg.protect_port, g_cfg.upstream.host,
			 g_cfg.upstream.port);
		return 0; /* 同端口模式到此为止，不需要 sk_lookup/connect4 */
	}

	/* ---- 以下是 redirect 模式（--listen 端口 != --protect-port 时）---- */

	/* 把受保护网段写进 LPM trie */
	map_fd = bpf_map__fd(g_skel->maps.protect_nets);
	for (int i = 0; i < g_net_count; i++) {
		struct lpm_key net_key = {
			.prefixlen = (uint32_t)g_nets[i].prefix,
			.ip = g_nets[i].ip,
		};
		uint32_t enabled = 1;
		bpf_map_update_elem(map_fd, &net_key, &enabled, BPF_ANY);
	}

	/*
	 * 把代理的 listen_fd 发布到 SOCKMAP。
	 * 神奇之处：value 只是 u32 的 fd，内核会自动查成 struct bpf_sock *，
	 * 后续 sk_lookup 里的 bpf_map_lookup_elem 拿到的就是 socket 引用。
	 */
	map_fd = bpf_map__fd(g_skel->maps.proxy_socks);
	bpf_map_update_elem(map_fd, &key, &listen_fd, BPF_ANY);

	/*
	 * sk_lookup 挂到网络命名空间（不是 cgroup！）。
	 * /proc/self/ns/net 是当前进程所在 netns 的句柄——所有网络对象
	 * （socket/路由/网卡）都属于某个 netns，sk_lookup 的作用域就是它。
	 */
	netns_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	g_sk_link = bpf_program__attach_netns(g_skel->progs.shield_sk_lookup,
					      netns_fd);
	close(netns_fd);

	/* connect4 挂到 cgroup，防本机客户端绕过重定向 */
	g_cg_link = attach_cgroup_prog(g_skel->progs.shield_connect4,
				       "/sys/fs/cgroup");

	return 0;
}

/* ---------- 3.8 main：把所有环节串起来 ---------- */

int main(int argc, char **argv)
{
	int listen_fd;

	/*
	 * 启动顺序非常关键（README 反复强调）：
	 *
	 *   1. 解析命令行参数（--listen/--upstream/--protect-port/--ca/...）
	 *   2. init tls   —— 加载证书、配置 mTLS 策略
	 *   3. listen     —— mtls_shield 先占住 9000！
	 *   4. bpf_setup  —— 挂 eBPF（此时改写规则才生效）
	 *   5. 启动后端   —— 后端的 bind(9000) 被改写到 127.0.0.1:19000
	 *   6. accept_loop —— 开始服务
	 *
	 * 如果顺序反了（后端先启动）：后端抢先把 9000 绑走（当时没有 eBPF 改写），
	 * mtls_shield 再启动时 bind 9000 直接 EADDRINUSE。
	 */
	parse_args(argc, argv);   /* 详见原文件，含端口/CIDR/allow-cn 解析 */
	install_signals();        /* SIGINT/SIGTERM -> g_stop；SIGUSR1 -> 打印统计 */

	if (tls_init() < 0)       /* B2/B3：构造 mTLS SSL_CTX */
		return 1;

	listen_fd = create_listener(); /* 占住对外端口 9000 */
	if (listen_fd < 0)
		return 1;

	if (bpf_setup(listen_fd) < 0) /* A：装载并挂载 eBPF */
		return 1;

	log_info("mtls_shield ready: listen %s:%d -> upstream %s:%d (protect tcp/%d)",
		 g_cfg.listen.host, g_cfg.listen.port,
		 g_cfg.upstream.host, g_cfg.upstream.port,
		 g_cfg.protect_port);

	accept_loop(listen_fd); /* B4/B5/B6：接连接、握手、转发 */

	/* ---- 优雅退出：解除 eBPF 挂载，避免系统残留改写规则 ---- */
	if (g_bind_link)
		bpf_link__destroy(g_bind_link); /* detach + close link */
	if (g_sk_link)
		bpf_link__destroy(g_sk_link);
	if (g_cg_link)
		bpf_link__destroy(g_cg_link);

	/* skeleton 销毁：内核里的 map/program 引用也随之释放 */
	if (g_skel)
		mtls_shield_bpf__destroy(g_skel);

	close(listen_fd);
	SSL_CTX_free(g_tls_ctx); /* 释放 SSL_CTX（私钥随之从内存清除） */
	return 0;
}

/* =====================================================================================
 * 第 4 部分：常见坑与自测清单（对照学习）
 * =====================================================================================
 *
 *  1. 字节序混乱：
 *     - sockaddr 里的 sin_port、BPF ctx->user_port：网络字节序
 *     - BPF ctx->local_port（sk_lookup）：主机字节序！
 *     - cfg map 里的端口统一存网络序，比较前看清各字段的语义。
 *
 *  2. eBPF 验证器报错常见原因：
 *     - map lookup 返回值没判空就解引用；
 *     - 循环没有上界（BPF 不允许 while(1) 里没有可证明的退出条件）；
 *     - 忘了 bpf_sk_release 导致引用泄漏（验证器直接拒绝）。
 *
 *  3. mTLS 调试三板斧：
 *     openssl s_client -connect 127.0.0.1:9000 -cert client.crt -key client.key -CAfile ca.crt
 *     看握手输出里的 "Verify return code"；不带 -cert 尝试应当失败（验证 FAIL_IF_NO_PEER_CERT）。
 *
 *  4. 启动顺序：
 *     mtls_shield 先启动（占 9000 + 挂 eBPF），后端后启动（bind 被改写到 19000）。
 *     验证：ss -ltnp | grep -E ':(9000|19000)' —— 9000 是 mtls_shield，19000 是后端。
 *
 *  5. 半关闭处理：
 *     relay_loop 里 client_eof 后必须继续转发后端剩余数据，最后 shutdown(SHUT_WR)，
 *     否则 HTTP 这类"请求端先关写"的协议会丢响应。
 *
 *  6. 资源释放对称性：
 *     SSL_get_peer_certificate -> X509_free
 *     bpf_map_lookup_elem(SOCKMAP) -> bpf_sk_release
 *     pthread_create -> pthread_detach（或 join）
 *     link/skel/SSL_CTX -> destroy/free，退出路径一个都不能少。
 *
 * =====================================================================================
 */
