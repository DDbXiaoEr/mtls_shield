#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

struct shield_cfg {
	__u32 enabled;
	__u32 backend_ip4;
	__u16 protect_port;
	__u16 proxy_port;
	__u16 backend_port;
	__u16 reserved;
};

struct lpm_key {
	__u32 prefixlen;
	__u32 ip;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct shield_cfg);
} shield_cfg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, __u32);
} protect_nets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} proxy_socks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

enum stat_key {
	STAT_SK_REDIRECT = 0,
	STAT_CONNECT_REDIRECT = 1,
	STAT_NO_SOCKET = 2,
	STAT_ASSIGN_ERROR = 3,
	STAT_SEEN = 4,
	STAT_PORT_MATCH = 5,
	STAT_BIND_REDIRECT = 6,
};

static __always_inline void stat_inc(__u32 key)
{
	__u64 *value = bpf_map_lookup_elem(&stats, &key);

	if (value)
		__sync_fetch_and_add(value, 1);
}

static __always_inline int net_is_protected(__u32 ip)
{
	struct lpm_key key = {
		.prefixlen = 32,
		.ip = ip,
	};

	return bpf_map_lookup_elem(&protect_nets, &key) != 0;
}

SEC("sk_lookup")
int shield_sk_lookup(struct bpf_sk_lookup *ctx)
{
	__u32 zero = 0;
	struct shield_cfg *cfg;
	struct bpf_sock *sk;
	__u32 sock_key = 0;
	long ret;

	stat_inc(STAT_SEEN);

	cfg = bpf_map_lookup_elem(&shield_cfg_map, &zero);
	if (!cfg)
		return SK_PASS;
	if (ctx->family != AF_INET || ctx->protocol != IPPROTO_TCP)
		return SK_PASS;
	if (!cfg->enabled ||
	    (__u16)ctx->local_port != bpf_ntohs(cfg->protect_port))
		return SK_PASS;

	stat_inc(STAT_PORT_MATCH);

	if (!net_is_protected(ctx->local_ip4))
		return SK_PASS;

	sk = bpf_map_lookup_elem(&proxy_socks, &sock_key);
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
	__u32 zero = 0;
	struct shield_cfg *cfg;

	cfg = bpf_map_lookup_elem(&shield_cfg_map, &zero);
	if (!cfg || !cfg->enabled || !cfg->backend_port)
		return 1;
	if ((__u16)ctx->user_port != cfg->protect_port)
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
	__u32 zero = 0;
	struct shield_cfg *cfg;

	cfg = bpf_map_lookup_elem(&shield_cfg_map, &zero);
	if (!cfg)
		return 1;
	if (!cfg->enabled || (__u16)ctx->user_port != cfg->protect_port)
		return 1;
	if (!net_is_protected(ctx->user_ip4))
		return 1;

	ctx->user_port = cfg->proxy_port;
	stat_inc(STAT_CONNECT_REDIRECT);
	return 1;
}

char LICENSE[] SEC("license") = "GPL";
