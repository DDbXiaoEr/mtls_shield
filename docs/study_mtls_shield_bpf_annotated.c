/*
 * =====================================================================================
 *  mtls_shield eBPF 程序学习注释版（study_mtls_shield_bpf_annotated.c）
 * =====================================================================================
 *
 *  【本文件用途】
 *  对应源文件 src/mtls_shield.bpf.c（约 165 行），逐行讲解 eBPF 内核态代码。
 *  本文件【不能直接编译】（注释量远超代码，且部分示例代码标注为"错误写法"），
 *  可编译版本请看 src/mtls_shield.bpf.c。
 *
 *  【eBPF 是什么？——30 秒版本】
 *  eBPF = 在【不改内核源码、不加载内核模块】的前提下，往内核里注入一小段
 *  受限的字节码程序，挂在预定义的"钩子点"（hook）上执行。本项目挂了两类钩子：
 *
 *    1. cgroup/bind4    —— 任何进程调用 bind(2) 绑 IPv4 时触发，
 *                          我们在内核里【改写】它要绑定的 IP:Port；
 *    2. sk_lookup       —— 入站 TCP 包要找"哪个 socket 接收"时触发，
 *                          我们可以把连接【改派】给指定 socket。
 *
 *  【为什么 eBPF 代码这么"别扭"？】
 *  因为程序要经过【验证器（verifier）】的严格检查才能装进内核，验证器要求：
 *    - 禁止无界循环（每个循环必须能静态证明会退出）
 *    - 禁止随意指针运算（指针来源必须可追溯）
 *    - 每次解引用前必须判空（map lookup 可能返回 NULL）
 *    - 只能调用内核白名单里的 bpf_* 辅助函数，不能用 printf/malloc 等 libc
 *    - 栈空间只有 512 字节
 *    - 指令数有上限（现代内核 100 万条，但越少越好）
 *  所以下面的代码会看到大量 if (!ptr) return ... 的防御式写法，这不是胆小，
 *  是验证器强制的。
 *
 *  【编译与装载流程（了解即可）】
 *    clang -target bpf -O2 -g -c mtls_shield.bpf.c -o mtls_shield.bpf.o
 *      ^ 必须 -target bpf 生成 BPF 字节码；-g 生成 BTF 调试信息（现代 libbpf 必需）
 *    bpftool gen skeleton mtls_shield.bpf.o > mtls_shield.skel.h
 *      ^ 生成用户态骨架头文件，让用户态像操作 C 结构体一样操作 map/program
 *    用户态调用 mtls_shield_bpf__open/load/attach 完成装载和挂载
 *
 *  【阅读路线图】
 *    第 1 节  头文件与宏
 *    第 2 节  共享数据结构（和用户态约定的 ABI）
 *    第 3 节  BPF map 定义（4 个 map 的类型选型与原理）
 *    第 4 节  辅助函数（stat_inc / net_is_protected）
 *    第 5 节  程序一：sk_lookup（连接劫持）
 *    第 6 节  程序二：cgroup/bind4（★ 核心：bind 端口透明改写）
 *    第 7 节  程序三：cgroup/connect4（出站连接改写）
 *    第 8 节  LICENSE 声明与验证器/调试技巧
 *
 * =====================================================================================
 */


/* =====================================================================================
 * 第 1 节：头文件与宏
 * ===================================================================================== */

/*
 * vmlinux.h —— eBPF 世界的"万能头文件"。
 *
 * 它由内核源码/BTF 自动生成（bpftool btf dump file /sys/kernel/btf/vmlinux format c），
 * 里面是【所有内核类型】的 C 定义：struct bpf_sock_addr、struct bpf_sk_lookup、
 * __u32/__u64、AF_INET、IPPROTO_TCP…… 一份就有几十万行。
 *
 * 为什么不用常规的 <linux/bpf.h>？
 *   BPF 程序不能包含标准 glibc 头文件（用户态的类型定义和内核不完全一致，
 *   还会带进一堆 BPF 环境用不了的声明）。vmlinux.h + BTF 是官方推荐的组合，
 *   类型和当前运行内核【严格一致】，跨内核版本编译也不怕结构体错位。
 */
#include "vmlinux.h"

/*
 * bpf_helpers.h —— bpf_* 辅助函数的声明 + SEC() 等宏。
 * 里面定义了我们能用的"内核 API"：
 *   bpf_map_lookup_elem()、bpf_map_update_elem()  —— map 读写
 *   bpf_sk_assign()、bpf_sk_release()              —— socket 操作（sk_lookup 专用）
 *   bpf_ntohs() 等字节序宏
 * 这些函数只是"声明"，真正的实现在内核里；BPF 验证器按函数 ID 映射到内核实现。
 */
#include <bpf/bpf_helpers.h>

/* bpf_endian.h —— bpf_ntohs/bpf_htons/bpf_ntohl 等字节序转换宏 */
#include <bpf/bpf_endian.h>

/*
 * vmlinux.h 在某些内核版本里没有 AF_INET / IPPROTO_TCP（它们是 POSIX 宏，
 * 不是内核类型），所以手动兜底定义。
 * AF_INET=2（IPv4 协议族）、IPPROTO_TCP=6（IP 协议号），这些值是内核 ABI，
 * 永远不会变，可以直接硬编码。
 */
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif


/* =====================================================================================
 * 第 2 节：共享数据结构（BPF 侧 <-> 用户态的 ABI 约定）
 * -------------------------------------------------------------------------------------
 * 这两个结构体在用户态 src/mtls_shield.c 里有【一模一样】的副本。
 * 两边布局必须逐字节一致（字段类型、顺序、对齐都要对上），否则用户态写的配置
 * BPF 读出来就是乱码。生产项目通常放进共享头文件（如 common.h）避免漂移。
 *
 * 布局一致的技巧：
 *   - 只用定宽整数（__u32/__u16），不要用 int/long（32/64 位平台宽度不同）
 *   - 按大小降序排列字段减少 padding
 *   - 用 pahole 或 BPF verifier 日志检查最终布局
 * ===================================================================================== */

/*
 * shield_cfg：配置表的 value。
 * 用户态通过 map 更新它，BPF 程序每次触发时实时读取——这就是 BPF 程序的
 * "运行时可配置"机制（程序字节码加载后不可改，但 map 随时可改）。
 */
struct shield_cfg {
	__u32 enabled;      /* 总开关：1=生效，0=全部放行（快速回滚用，不用卸载程序） */
	__u32 backend_ip4;  /* bind4 改写的目标 IP（网络字节序，如 127.0.0.1） */
	__u16 protect_port; /* 受保护端口 = 对外端口 9000（网络字节序，用户态 htons 后写入） */
	__u16 proxy_port;   /* mtls_shield 监听端口（redirect 模式的 connect4 改写目标） */
	__u16 backend_port; /* 后端内部端口 19000（网络字节序） */
	__u16 reserved;     /* 占位对齐：3 个 u16 后补 1 个，让结构体凑满 8 字节倍数 */
};

/*
 * lpm_key：LPM_TRIE map 的 key。
 * "前缀长度 + IP"的组合 = CIDR 表示法的二进制形式，如 10.0.0.0/8 变成
 * { prefixlen=8, ip=0x0a000000 }（网络字节序）。
 */
struct lpm_key {
	__u32 prefixlen; /* 前缀位数 0~32；32 = 精确匹配单个 IP */
	__u32 ip;        /* IP 地址（网络字节序） */
};


/* =====================================================================================
 * 第 3 节：BPF map 定义
 * -------------------------------------------------------------------------------------
 * BPF map = 内核里的【键值存储】，是 BPF 程序和用户态之间唯一的通信通道
 * （BPF 程序不能直接读写用户态内存，反之亦然）。
 *
 * 现代定义语法（BTF-style，libbpf 推荐）：
 *
 *   struct {
 *       __uint(type,   BPF_MAP_TYPE_XXX);   // map 类型
 *       __uint(max_entries, N);             // 容量
 *       __type(key,   K);                   // key 的 C 类型
 *       __type(value, V);                   // value 的 C 类型
 *   } name SEC(".maps");                    // 放进 ELF .maps 段，libbpf 自动识别
 *
 * SEC(".maps") 是关键：libbpf 加载 ELF 时扫描这个段，自动在内核创建 map，
 * 并把程序里的 map 引用重定位到真实 map。旧式写法要填 struct bpf_map_def
 * 并手动 bpf_object__find_map_by_name，现在基本淘汰了。
 * ===================================================================================== */

/*
 * map 1/4：shield_cfg_map —— ARRAY 类型，当"配置表"用。
 *
 * 【为什么是 ARRAY？】
 *   - key 只能是 0..max_entries-1 的整数（这里只有 key=0 一个槽位）
 *   - 槽位永久存在：lookup 永远成功（不存在"没插入"的情况），代码少一层判空分支
 *   - 没有哈希计算开销，访问是 O(1) 数组下标
 * 适用场景：单条配置、固定数量的统计表。不适合频繁增删的场景。
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);               /* 只有 1 个槽位 = 全局配置单例 */
	__type(key, __u32);                   /* key 恒为 0 */
	__type(value, struct shield_cfg);
} shield_cfg_map SEC(".maps");

/*
 * map 2/4：protect_nets —— LPM_TRIE 类型，存受保护的 IP 网段。
 *
 * 【LPM = Longest Prefix Match，最长前缀匹配】
 *   和内核路由表同一数据结构：查 IP 10.1.2.3，表里同时有 10.0.0.0/8 和
 *   10.1.0.0/16 时命中前缀更长的 10.1.0.0/16。
 *
 * 【BPF_F_NO_PREALLOC 标志】
 *   LPM trie 的节点大小不固定（取决于前缀树形状），无法预分配，
 *   必须设此标志让内核在插入时动态分配节点。忘了这个标志，map 创建直接失败。
 *
 * 【max_entries=128】最多 128 个网段，对应用户态 MAX_NETS。
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_NO_PREALLOC); /* LPM_TRIE 必须带这个标志 */
	__type(key, struct lpm_key);
	__type(value, __u32);                 /* value 只当存在性标记用，内容无所谓 */
} protect_nets SEC(".maps");

/*
 * map 3/4：proxy_socks —— SOCKMAP 类型，存 socket 引用（redirect 模式用）。
 *
 * 【SOCKMAP 的特殊之处】
 *   value 声明为 __u32（用户态写入的是 fd），但内核内部存的是
 *   struct bpf_sock *（socket 对象引用）。用户态写 fd，BPF 程序读出
 *   可直接传给 bpf_sk_assign() 的 socket 指针——内核自动完成 fd->sock 转换。
 *
 *   这是 eBPF "socket 编程"的基石：让 BPF 程序操控内核 socket 对象，
 *   实现连接重定向/负载均衡（Envoy、Cilium 的透明代理都靠它）。
 *
 * 【max_entries=4】冗余留了几个槽位，实际只用 key=0 一个。
 */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);                 /* 用户态写 listen_fd，内核转成 bpf_sock */
} proxy_socks SEC(".maps");

/*
 * map 4/4：stats —— PERCPU_ARRAY 类型，统计计数器。
 *
 * 【为什么统计要用 per-CPU？】
 *   普通 map 被多个 CPU 同时更新时需要锁或原子操作，网络热路径上这是
 *   明显的性能瓶颈。PERCPU_ARRAY 给每个 CPU 一份独立副本：
 *     - 写（BPF 侧）：无锁，写自己 CPU 的副本
 *     - 读（用户态侧）：bpf_map_lookup_elem 返回 ncpu 个值的数组，求和即可
 *   代价是内存占用 x CPU 核数，但计数器只有 8 x 8 字节，忽略不计。
 *
 * 【enum stat_key 的 7 个下标】和 max_entries=8 对应（留 1 个备用）。
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

/* 统计项下标（= map key）。命名清晰对排障至关重要——bpftool 里看到数字能对上名字 */
enum stat_key {
	STAT_SK_REDIRECT = 0,   /* sk_lookup 成功改派的次数 */
	STAT_CONNECT_REDIRECT,  /* connect4 改写的次数 */
	STAT_NO_SOCKET,         /* SOCKMAP 里没放代理 socket 的异常次数（配置遗漏） */
	STAT_ASSIGN_ERROR,      /* bpf_sk_assign 失败次数 */
	STAT_SEEN,              /* sk_lookup 总触发次数 */
	STAT_PORT_MATCH,        /* 其中命中保护端口的次数 */
	STAT_BIND_REDIRECT,     /* bind4 改写次数——★ 同端口模式的核心指标 */
};


/* =====================================================================================
 * 第 4 节：辅助函数
 * ===================================================================================== */

/*
 * stat_inc：统计自增。
 *
 * __always_inline：
 *   强制内联。BPF 里函数调用会展开成 call 指令，受"调用深度上限"限制
 *   （验证器要求调用栈有界），小工具函数一律内联最省心，也避免调用开销。
 *
 * __sync_fetch_and_add(value, 1)：
 *   GCC 原子自增（lock xadd）。虽然 PERCPU_ARRAY 同一 CPU 上的并发不常见，
 *   但 BPF 程序可能在【软中断/抢占上下文】重入（比如正在处理的包又被打断），
 *   原子操作是稳妥写法。BPF 里也可用 __sync_fetch_and_add 的 BPF 原子变体
 *   __sync_fetch_and_add 在 clang 下直接映射成 BPF atomic 指令。
 *
 * 验证器注意：bpf_map_lookup_elem 返回值必须判空！这里 if (value) 就是给
 * 验证器看的证明——"只有非空才解引用"。PERCPU_ARRAY 的 lookup 实际不会失败
 * （槽位恒存在），但语法上这个判断不能省，省了验证器直接拒绝加载。
 */
static __always_inline void stat_inc(__u32 key)
{
	__u64 *value = bpf_map_lookup_elem(&stats, &key);

	if (value) /* 验证器强制：解引用前必须证明非空 */
		__sync_fetch_and_add(value, 1);
}

/*
 * net_is_protected：IP 是否属于受保护网段。
 *
 * 查询技巧：构造 prefixlen=32 的完整 key 去查 LPM trie。
 * LPM 的语义是"用 key 里的 IP 去匹配表中所有条目，返回前缀最长的命中者"，
 * 所以：
 *   表里有 {8, 10.0.0.0}，查 {32, 10.1.2.3} -> 命中（10.1.2.3 落在 10/8 内）
 *   表里有 {8, 10.0.0.0}，查 {32, 192.168.1.1} -> 不命中
 * 返回非空指针 = 受保护。
 *
 * 另一个惯用法：直接查 {prefixlen=0} 判断"表是否为空/是否有 catch-all"，
 * 但这里不需要。
 */
static __always_inline int net_is_protected(__u32 ip)
{
	struct lpm_key key = {
		.prefixlen = 32, /* 拿整个 IP 当 32 位前缀去查，让 LPM 自由匹配更短前缀 */
		.ip = ip,
	};

	return bpf_map_lookup_elem(&protect_nets, &key) != 0;
}


/* =====================================================================================
 * 第 5 节：程序一 —— SEC("sk_lookup") 入站连接劫持
 * -------------------------------------------------------------------------------------
 * 【挂载点：sk_lookup】
 *   触发时机：一个 TCP 包（SYN）到达本机，内核要为它【匹配接收 socket】时。
 *   正常流程：内核按四元组查监听 socket（9000 的 listener 谁在听？）。
 *   我们能做的：用 bpf_sk_assign() 改变"由谁来接收这个连接"。
 *
 * 【与 cgroup/bind4 的分工】
 *   - 同端口模式（默认）：只用 bind4，本程序不参与
 *   - redirect 模式：mtls_shield 监听在别的端口，客户端却 connect 9000，
 *     就靠本程序把连接"递"给代理 socket
 *
 * 【ctx 结构：struct bpf_sk_lookup】关键字段：
 *   ctx->family       协议族（AF_INET=2）
 *   ctx->protocol     协议（IPPROTO_TCP=6）
 *   ctx->local_ip4    目的 IP（包要送达的地址，主机看不懂时按网络序存）
 *   ctx->local_port   目的端口——注意是【主机字节序】！
 *   ctx->remote_ip4/remote_port  源地址/源端口（客户端）
 *
 * 【返回值约定（sk_lookup 专属）】
 *   SK_PASS (1) = 放行，继续正常 socket 匹配（若 bpf_sk_assign 成功，
 *                 匹配结果已被我们覆盖，包会进改派的 socket）
 *   SK_DROP (0) = 丢包
 *   注意：和 cgroup 程序的 0/1 语义【相反】，跨挂载点写代码极易搞混！
 * ===================================================================================== */
SEC("sk_lookup")
int shield_sk_lookup(struct bpf_sk_lookup *ctx)
{
	__u32 zero = 0; /* ARRAY map 的唯一 key */
	struct shield_cfg *cfg;
	struct bpf_sock *sk;
	__u32 sock_key = 0;
	long ret;

	/*
	 * 先记"程序被触发"。调试期非常有用：
	 * 如果 STAT_SEEN 不增长，说明程序压根没被调用（挂载点错了/包没到这层）；
	 * 如果 SEEN 增长但 PORT_MATCH 不增长，说明端口判断没过（字节序问题！）。
	 * 用统计计数器代替 printf——BPF 里没有 printf。
	 */
	stat_inc(STAT_SEEN);

	cfg = bpf_map_lookup_elem(&shield_cfg_map, &zero);
	if (!cfg)        /* ARRAY 理论上恒命中，但验证器要求判空，且防御未来变化 */
		return SK_PASS;
	if (!cfg->enabled) /* 快速开关：用户态把 enabled 改 0，程序立即"隐身" */
		return SK_PASS;

	/* 只处理 IPv4 + TCP；UDP/ICMP/IPv6 一律不碰（IPv6 是已知限制，见 README） */
	if (ctx->family != AF_INET || ctx->protocol != IPPROTO_TCP)
		return SK_PASS;

	/*
	 * ★ 端口比较的字节序陷阱（本程序最易错的一行）★
	 *
	 *   ctx->local_port    : __u16，【主机字节序】（sk_lookup 上下文的约定）
	 *   cfg->protect_port  : __u16，【网络字节序】（用户态写入时 htons 过）
	 *
	 * 两者直接 != 比较，在小端机器上 9000(0x2328) 会变成 0x2823=10275，
	 * 永远匹配不上。所以这里用 bpf_ntohs() 把配置转回主机序再比。
	 *
	 * 对照：下面 bind4 里 ctx->user_port 是【网络字节序】（bind 的 sockaddr
	 * 语义），比较时就【不能】转换。同是"端口"，不同上下文字节序不同——
	 * 这是 eBPF 网络编程第一坑。
	 *
	 * (__u16) 强转：ctx->local_port 实际类型可能是 u32 位域/带高位，
	 * 截断成 u16 再比较，避免高位脏数据干扰。
	 */
	if ((__u16)ctx->local_port != bpf_ntohs(cfg->protect_port))
		return SK_PASS;

	stat_inc(STAT_PORT_MATCH);

	/*
	 * 目标 IP 检查：只对受保护网段内的地址生效。
	 * 典型用法：--protect-net 10.0.0.0/8 只保护内网服务的端口，
	 * 同一台机器上公网 IP 的同端口服务不受影响。
	 */
	if (!net_is_protected(ctx->local_ip4))
		return SK_PASS;

	/*
	 * 从 SOCKMAP 取代理 socket。
	 * 用户态在 bpf_setup 里做过 bpf_map_update_elem(proxy_socks, 0, &listen_fd)，
	 * 这里 lookup 出来的是内核把 fd 解析成的 struct bpf_sock *。
	 */
	sk = bpf_map_lookup_elem(&proxy_socks, &sock_key);
	if (!sk) {
		/* 用户态忘了写入 / 写入失败——统计暴露配置问题 */
		stat_inc(STAT_NO_SOCKET);
		return SK_PASS;
	}

	/*
	 * ★ bpf_sk_assign：sk_lookup 程序存在的全部意义 ★
	 *   把【当前正在匹配的连接】指派给指定 socket。
	 *   之后内核不再走自己的监听表匹配，直接把包送进这个 socket 的接收队列。
	 *   相当于在内核 socket 查找路径上"改志愿"。
	 *
	 *   参数：(ctx, sk, flags)。flags 目前必须为 0。
	 *   返回：0 成功，负数失败（比如 socket 状态不对、没有接收能力）。
	 */
	ret = bpf_sk_assign(ctx, sk, 0);

	/*
	 * ★ bpf_sk_release：必须调用，否则验证器拒绝加载 ★
	 *
	 * SOCKMAP 的 lookup 返回的是"带引用计数的 socket 引用"，
	 * 用完不 release 会造成内核 socket 对象泄漏（引用计数永不归零）。
	 * 验证器会静态跟踪引用的获取/释放配对，缺一个就报
	 *   "Unreleased reference" 直接拒绝。
	 * 这是 BPF 引用规则（reference handling）的入门课：
	 *   lookup-sockmap / bpf_sk_lookup_tcp 等 -> 拿到引用 -> 必须 release。
	 */
	bpf_sk_release(sk);

	if (ret) {
		stat_inc(STAT_ASSIGN_ERROR);
		return SK_PASS; /* 失败就放行走原生匹配，宁可绕过也不丢连接 */
	}

	stat_inc(STAT_SK_REDIRECT);

	/*
	 * 即使改派成功也返回 SK_PASS（不是 SK_DROP！）：
	 * SK_PASS 表示"包继续正常处理"，只是接收方已被我们换掉。
	 * 返回 SK_DROP 会把 SYN 直接丢弃——那是防火墙行为，不是代理行为。
	 */
	return SK_PASS;
}


/* =====================================================================================
 * 第 6 节：程序二 —— SEC("cgroup/bind4") ★ 项目核心：透明改写 bind() ★
 * -------------------------------------------------------------------------------------
 * 【挂载点：cgroup/bind4】
 *   触发时机：cgroup 内任何进程调用 bind(2) 绑定 IPv4 地址时，
 *   在【内核真正执行绑定之前】插入执行。
 *
 * 【ctx 结构：struct bpf_sock_addr】关键字段：
 *   ctx->user_ip4   准备绑定的 IP（网络字节序）
 *   ctx->user_port  准备绑定的端口（网络字节序 __be16，sockaddr 语义）
 *   ctx->protocol   协议
 *   这就是内核将要使用的 sockaddr 的"活体"，程序直接改字段 = 改绑定参数。
 *
 * 【工作原理】
 *   后端代码写的是 bind(fd, {0.0.0.0, 9000})，进程毫无感知；
 *   等 bind 系统调用进入内核，本程序把参数改成 {127.0.0.1, 19000}；
 *   内核继续用改后的参数执行绑定。结果：
 *     - 后端以为自己监听 9000（它代码里的端口常量没变）
 *     - 实际监听 127.0.0.1:19000（getsockname 能看到真实值）
 *     - 9000 被腾出来给 mtls_shield 占用做 TLS 终结
 *
 * 【返回值约定（cgroup/bind4 专属）】
 *   1 = 允许 bind（继续执行，用改写后的参数）
 *   0 = 拒绝 bind（系统调用返回 EACCES/EPERM 类错误）
 *   和 sk_lookup 的 SK_PASS=1/SK_DROP=0 方向一致，但语义文档不同，
 *   写新挂载点程序时务必查对应的手册（man bpf-helpers 各 ctx 章节）。
 *
 * 【安全性副作用（README 有说明）】
 *   后端被强制绑到 127.0.0.1，外部无法绕过 TLS 直连明文后端——
 *   这是"顺手"实现的一层防护：即使有人想跳过 mtls_shield 直连 19000，
 *   从外部网络也连不上（回环地址）。
 * ===================================================================================== */
SEC("cgroup/bind4")
int shield_bind4(struct bpf_sock_addr *ctx)
{
	__u32 zero = 0;
	struct shield_cfg *cfg;

	cfg = bpf_map_lookup_elem(&shield_cfg_map, &zero);

	/*
	 * 三个条件都不满足才干预：
	 *   cfg 存在、开关打开、后端端口已配置（backend_port=0 说明用户态
	 *   没启用同端口改写，比如 redirect 模式下）。
	 * 任一不满足 -> 返回 1（允许 bind，完全不干预）。
	 */
	if (!cfg || !cfg->enabled || !cfg->backend_port)
		return 1;

	/*
	 * 端口过滤：只改写"绑定受保护端口 9000"的 bind。
	 *
	 * 字节序：ctx->user_port 是 __be16（网络字节序），cfg->protect_port
	 * 也是网络字节序——【直接比较，不要转换】！
	 * 如果这里也套个 bpf_ntohs，就永远匹配不上（和 sk_lookup 正好相反）。
	 * 判断依据：bind(2) 的 sockaddr_in.sin_port 本来就是网络序，上下文
	 * 保持了一致性。记住口诀：【sock_addr 上下文的端口都是网络序】。
	 *
	 * 这个过滤还保证了：系统里其他服务 bind 自己的端口（80、3306……）
	 * 完全不受影响，只有 9000 会被"搬家"。
	 */
	if ((__u16)ctx->user_port != cfg->protect_port)
		return 1;

	/* --- 核心动刀：原地改写内核即将使用的 sockaddr --- */

	/* 端口改写：9000 -> 19000（配置里的 backend_port） */
	ctx->user_port = cfg->backend_port;

	/*
	 * IP 改写：可选但强烈建议。把绑定地址从 0.0.0.0 收紧到 127.0.0.1。
	 *   cfg->backend_ip4 由用户态填好（通常是 g_upstream_addr.sin_addr.s_addr，
	 *   已是网络序）。为 0 时跳过（用户态没配）。
	 *
	 * 为什么必须收紧？如果后端仍绑 0.0.0.0:19000，攻击者可以从外部直连
	 * 19000 绕过 mTLS。改绑 127.0.0.1 后明文通道只在本机可达，
	 * mTLS 强制性才成立。一行代码买到一大截安全。
	 */
	if (cfg->backend_ip4)
		ctx->user_ip4 = cfg->backend_ip4;

	stat_inc(STAT_BIND_REDIRECT); /* 同端口模式的健康指标，排障先看它 */

	/*
	 * 返回 1 = 【允许】bind 继续执行！
	 *
	 * 常见误解：以为改写完要返回 0。错！返回 0 是【拒绝】bind，
	 * 系统调用会直接报错，后端启动就崩了。我们要的是"改完放行"：
	 * 内核接着拿改写后的 {127.0.0.1, 19000} 去做真正的端口绑定。
	 */
	return 1;
}


/* =====================================================================================
 * 第 7 节：程序三 —— SEC("cgroup/connect4") 出站连接改写（redirect 模式补充）
 * -------------------------------------------------------------------------------------
 * 【挂载点：cgroup/connect4】
 *   触发时机：cgroup 内任何进程调用 connect(2) 连 IPv4 目标时，执行前触发。
 *   ctx 同样是 struct bpf_sock_addr，user_ip4/user_port 是【目标】地址。
 *
 * 【为什么需要它？sk_lookup 不够吗？】
 *   sk_lookup 处理的是"入站包找 socket"。但【本机客户端】connect(9000) 时，
 *   包走回环直接进本机的监听表匹配，某些内核路径下 sk_lookup 可能不触发
 *   或行为不同。所以在 connect 系统调用层把目标端口直接改成代理端口，
 *   双保险，保证本机客户端也被重定向。
 *
 *   同端口模式（默认）不挂载本程序——bind4 一个就够了。
 *
 * 【字节序】
 *   ctx->user_port 是网络字节序，cfg->protect_port 也是网络序 -> 直接比较。
 *   ctx->user_ip4 传给 net_is_protected 做 LPM 匹配（LPM 的 key 也是网络序，
 *   两边一致）。
 * ===================================================================================== */
SEC("cgroup/connect4")
int shield_connect4(struct bpf_sock_addr *ctx)
{
	__u32 zero = 0;
	struct shield_cfg *cfg;

	cfg = bpf_map_lookup_elem(&shield_cfg_map, &zero);
	if (!cfg)
		return 1;

	/* 开关未开 / 目标不是保护端口 -> 不干预 */
	if (!cfg->enabled || (__u16)ctx->user_port != cfg->protect_port)
		return 1;

	/* 目标 IP 不在保护网段 -> 不干预（防止误伤连到别处 9000 的正常流量） */
	if (!net_is_protected(ctx->user_ip4))
		return 1;

	/* 改写目标端口：connect 9000 实际连到代理的 listen 端口 */
	ctx->user_port = cfg->proxy_port;

	stat_inc(STAT_CONNECT_REDIRECT);

	/* 放行（返回 1），但目标已被偷换——"透明代理"的透明二字就在这 */
	return 1;
}


/* =====================================================================================
 * 第 8 节：LICENSE 声明、验证器与调试技巧
 * ===================================================================================== */

/*
 * ★★★ 这一行不能删！★★★
 *
 * BPF 程序必须声明 GPL 兼容许可证，否则：
 *   1. 内核里大量 GPL-only 辅助函数（bpf_sk_assign、bpf_sk_release 等）
 *      不可用——加载时报 "unknown func" 或被验证器拒绝；
 *   2. 某些内核直接拒绝加载未声明 license 的程序。
 *
 * SEC("license") 告诉 libbpf 把这个字符串放进 ELF 的 license 段，
 * 加载时内核读取它并检查 GPL 兼容性。常见合法值："GPL"、"GPL v2"、
 * "Dual BSD/GPL"。"Proprietary" 之类的值会导致 GPL-only 函数不可用。
 */
char LICENSE[] SEC("license") = "GPL";


/* =====================================================================================
 * 附录 A：验证器（verifier）速查 —— 为什么代码要写成这样
 * =====================================================================================
 *
 *  1. 判空是强制的：
 *     bad :  v = bpf_map_lookup_elem(...); *v += 1;          // 验证器拒绝
 *     good:  v = bpf_map_lookup_elem(...); if (v) *v += 1;    // 通过
 *
 *  2. 循环必须有界（旧内核完全禁循环，5.3+ 允许可证明有界的循环）：
 *     bad :  while (1) { ... }                 // 拒绝
 *     good:  #pragma unroll
 *            for (int i = 0; i < 8; i++) { ... }  // 展开后无循环，通过
 *
 *  3. 引用必须配对释放：
 *     sk = bpf_map_lookup_elem(&proxy_socks, ...);  // 拿到引用
 *     ... 使用 sk ...
 *     bpf_sk_release(sk);                            // 必须释放，否则拒绝加载
 *
 *  4. 栈只有 512 字节：大缓冲放 per-CPU map 或用全局变量，别放栈上。
 *
 *  5. 指令数上限：程序越长加载越慢，热路径（每个包都跑）要精简。
 *     加载失败时内核日志会说 "processed N instructions"，dmesg 看详情。
 *
 * 附录 B：调试三板斧
 *
 *  1. 统计计数器（本程序已内置）：
 *     sudo bpftool map dump name stats   // 或用户态 SIGUSR1 触发打印
 *     观察 STAT_SEEN / STAT_PORT_MATCH / STAT_BIND_REDIRECT 的增长，
 *     定位"程序没跑 / 端口没匹配 / 改写没发生"在哪一环断了。
 *
 *  2. bpftool 看挂载状态：
 *     sudo bpftool link list             // 确认 bind4/sk_lookup 链接存在
 *     sudo bpftool prog show name shield_bind4
 *
 *  3. verbose 日志：libbpf 打开 debug 输出（用户态设 LIBBPF_LOG_LEVEL=debug
 *     或 libbpf_set_print），加载失败时能看到验证器的完整拒绝理由——
 *     它会精确到"第几条指令、哪个寄存器状态不合法"，照着改就行。
 *
 * 附录 C：本程序的正确性自查清单
 *
 *  [ ] 字节序：sk_lookup 比较端口用了 bpf_ntohs，bind4/connect4 没用 —— 对
 *  [ ] bind4 返回 1（放行改写后的 bind），不是 0 —— 对
 *  [ ] bpf_sk_assign 后紧跟 bpf_sk_release —— 对
 *  [ ] 每个 map lookup 都判空后才解引用 —— 对
 *  [ ] LICENSE = "GPL" —— 对
 *  [ ] LPM_TRIE 带 BPF_F_NO_PREALLOC —— 对
 *
 * =====================================================================================
 */
