#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

/*
 * 每个被代理的原端口一条配置，key 是主机字节序的端口号。
 * 同一个 eBPF 对象由主进程加载一次，所有转发子进程共享；
 * 端口索引与用户态 --listenport/--protect_port/--upstream 的列表顺序一致。
 */
#define SHIELD_MAX_PORTS 64
#define SHIELD_MODE_SAME_PORT 1
#define SHIELD_MODE_REDIRECT 2

struct shield_port_cfg {
	__u32 enabled;
	__u32 backend_ip4;
	__u16 proxy_port;
	__u16 backend_port;
	__u16 mode;
	__u16 reserved;
};

struct lpm_key {
	__u32 prefixlen;
	__u32 ip;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SHIELD_MAX_PORTS);
	__type(key, __u32);
	__type(value, struct shield_port_cfg);
} shield_cfg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, __u32);
} protect_nets SEC(".maps");

struct {
	/* SOCKHASH 支持任意 32 位 key，这里直接用原端口做索引 */
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, SHIELD_MAX_PORTS);
	__type(key, __u32);
	__type(value, __u32);
} proxy_socks SEC(".maps");

/*
 * 统计事件通过 ringbuf 推给用户态累加。ringbuf 是单生产者/单消费者共享
 * 缓冲区，不需要 per-CPU 副本，也不会像 perf buffer 那样每 CPU 一个环。
 * 注意：缓冲区满时 bpf_ringbuf_reserve 会失败，这条事件被丢弃，
 * 用户态统计因此是“观察到的事件数”，不是严格计数；对当前每个连接
 * 才触发一次的事件量级来说足够。若要严格计数，应在 reserve 失败时
 * 回退到一个小型 per-CPU 丢弃计数器。
 */
struct stat_event {
	__u32 key;
	__u32 pad;
	__u64 ts;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} stat_events SEC(".maps");

enum stat_key {
	STAT_SK_REDIRECT = 0,
	STAT_CONNECT_REDIRECT = 1,
	STAT_NO_SOCKET = 2,
	STAT_ASSIGN_ERROR = 3,
	STAT_SEEN = 4,
	STAT_PORT_MATCH = 5,
	STAT_BIND_REDIRECT = 6,
	STAT_MAX = 7,
};

static __always_inline void stat_inc(__u32 key)
{
	struct stat_event *ev;

	ev = bpf_ringbuf_reserve(&stat_events, sizeof(*ev), 0);
	if (!ev)
		return;

	ev->key = key;
	ev->ts = bpf_ktime_get_ns();
	bpf_ringbuf_submit(ev, 0);
}

static __always_inline int net_is_protected(__u32 ip)
{
	struct lpm_key key = {
		.prefixlen = 32,
		.ip = ip,
	};

	return bpf_map_lookup_elem(&protect_nets, &key) != 0;
}

static __always_inline struct shield_port_cfg *port_cfg(__u32 port)
{
	return bpf_map_lookup_elem(&shield_cfg_map, &port);
}

SEC("sk_lookup")
int shield_sk_lookup(struct bpf_sk_lookup *ctx)
{
	__u32 port;
	struct shield_port_cfg *cfg;
	struct bpf_sock *sk;
	long ret;

	stat_inc(STAT_SEEN);

	if (ctx->family != AF_INET || ctx->protocol != IPPROTO_TCP)
		return SK_PASS;

	port = (__u32)(__u16)ctx->local_port;
	cfg = port_cfg(port);
	if (!cfg) {
		/* 某些内核里 local_port 是网络字节序，做一次兼容查找 */
		port = (__u32)bpf_ntohs((__u16)ctx->local_port);
		cfg = port_cfg(port);
	}
	if (!cfg || !cfg->enabled || cfg->mode != SHIELD_MODE_REDIRECT)
		return SK_PASS;

	stat_inc(STAT_PORT_MATCH);

	if (!net_is_protected(ctx->local_ip4))
		return SK_PASS;

	sk = bpf_map_lookup_elem(&proxy_socks, &port);
	if (!sk) {
		stat_inc(STAT_NO_SOCKET);
		return SK_PASS;
	}

	ret = bpf_sk_assign(ctx, sk, 0);
	bpf_sk_release(sk);
	if (ret) {
		stat_inc(STAT_ASSIGN_ERROR);
		return SK_PASS;
	}

	stat_inc(STAT_SK_REDIRECT);
	return SK_PASS;
}

SEC("cgroup/bind4")
int shield_bind4(struct bpf_sock_addr *ctx)
{
	__u32 port;
	struct shield_port_cfg *cfg;

	port = (__u32)bpf_ntohs((__u16)ctx->user_port);
	cfg = port_cfg(port);
	if (!cfg || !cfg->enabled || cfg->mode != SHIELD_MODE_SAME_PORT ||
	    !cfg->backend_port)
		return 1;

	ctx->user_port = cfg->backend_port;
	if (cfg->backend_ip4)
		ctx->user_ip4 = cfg->backend_ip4;

	stat_inc(STAT_BIND_REDIRECT);
	return 1;
}

SEC("cgroup/connect4")
int shield_connect4(struct bpf_sock_addr *ctx)
{
	__u32 port;
	struct shield_port_cfg *cfg;

	port = (__u32)bpf_ntohs((__u16)ctx->user_port);
	cfg = port_cfg(port);
	if (!cfg || !cfg->enabled || cfg->mode != SHIELD_MODE_REDIRECT)
		return 1;
	if (!net_is_protected(ctx->user_ip4))
		return 1;

	ctx->user_port = cfg->proxy_port;
	stat_inc(STAT_CONNECT_REDIRECT);
	return 1;
}

char LICENSE[] SEC("license") = "GPL";
