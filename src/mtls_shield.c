#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "mtls_shield.skel.h"

#define MAX_INSTANCES 64
#define MAX_NETS 128
#define MAX_ALLOW_CN 16
#define RELAY_BUF_SIZE 65536

/* 与 src/mtls_shield.bpf.c 中的定义保持一致 */
#define SHIELD_MODE_SAME_PORT 1
#define SHIELD_MODE_REDIRECT 2

struct endpoint {
	char host[256];
	int port;
};

/* 与 BPF shield_cfg_map 的 value 布局保持一致 */
struct shield_port_cfg {
	uint32_t enabled;
	uint32_t backend_ip4;
	uint16_t proxy_port;
	uint16_t backend_port;
	uint16_t mode;
	uint16_t reserved;
};

struct net_cidr {
	uint32_t ip;
	uint32_t mask;
	int prefix;
};

struct lpm_key {
	uint32_t prefixlen;
	uint32_t ip;
};

struct upstream_pool {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	int *fds;
	int count;
	int capacity;
	int stopping;
	int running;
	pthread_t thread;
	unsigned long long hits;
	unsigned long long misses;
};

/*
 * 一个实例对应一个被终结的端口，也对应一个转发子进程。
 * 列表参数按数组下标一一对应：listen_port[i]/protect_port[i]/
 * upstream[i]/ca[i]/cert[i]/key[i]。
 */
struct instance_cfg {
	int index;
	int listen_port;
	int protect_port;
	struct endpoint upstream;
	struct sockaddr_in upstream_addr;
	const char *ca_file;
	const char *cert_file;
	const char *key_file;
	int same_port;
	int listen_fd;
	pid_t pid;
	int restart_delay;
	long long restart_at_ms;
	long long started_at_ms;
	struct upstream_pool pool;
	int active_conns;
};

struct app_config {
	struct instance_cfg inst[MAX_INSTANCES];
	int count;
	char listen_host[256];
	int handshake_timeout;
	int max_conns;
	int pool_size;
	int local_redirect;
	int verbose;
};

struct conn_arg {
	struct instance_cfg *inst;
	int fd;
	struct sockaddr_storage peer;
	socklen_t peer_len;
	char peer_str[INET6_ADDRSTRLEN + 16];
};

static struct app_config g_cfg = {
	.listen_host = "0.0.0.0",
	.handshake_timeout = 10,
	.max_conns = 512,
	.pool_size = 32,
	.local_redirect = 1,
	.verbose = 0,
};

/* 当前子进程正在服务的实例；父进程中为 NULL */
static struct instance_cfg *g_inst;

static struct net_cidr g_nets[MAX_NETS];
static int g_net_count;
static char *g_allow_cns[MAX_ALLOW_CN];
static int g_allow_cn_count;

static SSL_CTX *g_tls_ctx;
static struct mtls_shield_bpf *g_skel;
static struct bpf_link *g_sk_link;
static struct bpf_link *g_cg_link;
static struct bpf_link *g_bind_link;

static volatile sig_atomic_t g_stop;
static volatile sig_atomic_t g_want_stats;
static volatile sig_atomic_t g_child_event;

static char g_tag_buf[64];
static const char *g_tag = "main";

/* 参数列表（逗号分隔） */
static char *g_listen_items[MAX_INSTANCES];
static int g_listen_count;
static char *g_protect_items[MAX_INSTANCES];
static int g_protect_count;
static char *g_upstream_items[MAX_INSTANCES];
static int g_upstream_count;
static char *g_ca_items[MAX_INSTANCES];
static int g_ca_count;
static char *g_cert_items[MAX_INSTANCES];
static int g_cert_count;
static char *g_key_items[MAX_INSTANCES];
static int g_key_count;

static void log_msg(const char *level, const char *fmt, va_list ap)
{
	char ts[32];
	struct tm tm;
	time_t now = time(NULL);

	localtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
	fprintf(stderr, "[%s] [%s] %-5s ", ts, g_tag, level);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
}

static void log_info(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_msg("INFO", fmt, ap);
	va_end(ap);
}

static void log_warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_msg("WARN", fmt, ap);
	va_end(ap);
}

static void log_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_msg("ERROR", fmt, ap);
	va_end(ap);
}

static const char *ssl_error_string(void)
{
	static __thread char buf[256];
	unsigned long err = ERR_peek_last_error();

	if (!err)
		return "unknown TLS error";
	ERR_error_string_n(err, buf, sizeof(buf));
	return buf;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !g_cfg.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int parse_int(const char *s, int min, int max, int *out)
{
	char *end = NULL;
	long value;

	errno = 0;
	value = strtol(s, &end, 10);
	if (errno || !end || *end != '\0' || value < min || value > max)
		return -1;
	*out = (int)value;
	return 0;
}

static int parse_endpoint(const char *s, struct endpoint *ep)
{
	char buf[320];
	char *colon;
	int port;

	snprintf(buf, sizeof(buf), "%s", s);
	colon = strrchr(buf, ':');
	if (!colon || colon == buf)
		return -1;
	*colon = '\0';
	if (parse_int(colon + 1, 1, 65535, &port))
		return -1;
	if (strlen(buf) >= sizeof(ep->host))
		return -1;
	snprintf(ep->host, sizeof(ep->host), "%s", buf);
	ep->port = port;
	return 0;
}

static int split_csv(char *s, char **out, int max, const char *name)
{
	char *p = s;
	int n = 0;

	while (p && *p) {
		char *comma = strchr(p, ',');
		char *end;

		if (comma)
			*comma = '\0';
		end = p + strlen(p);
		while (*p == ' ' || *p == '\t')
			p++;
		while (end > p && (end[-1] == ' ' || end[-1] == '\t'))
			*--end = '\0';
		if (*p == '\0') {
			log_error("%s has an empty item", name);
			return -1;
		}
		if (n >= max) {
			log_error("%s has too many items (max %d)", name, max);
			return -1;
		}
		out[n++] = p;
		if (!comma)
			break;
		p = comma + 1;
	}

	if (n == 0) {
		log_error("%s needs at least one item", name);
		return -1;
	}
	return n;
}

static int parse_list_option(char *arg, char **items, int *count, int max,
			     const char *name)
{
	int n = split_csv(arg, items, max, name);

	if (n < 0) {
		*count = 0;
		return -1;
	}
	*count = n;
	return 0;
}

static int parse_cidr(const char *s, struct net_cidr *out)
{
	char buf[128];
	char *slash;
	struct in_addr addr;
	int prefix = 32;

	snprintf(buf, sizeof(buf), "%s", s);
	slash = strchr(buf, '/');
	if (slash) {
		*slash = '\0';
		if (parse_int(slash + 1, 0, 32, &prefix))
			return -1;
	}
	if (inet_pton(AF_INET, buf, &addr) != 1)
		return -1;

	out->ip = addr.s_addr;
	out->prefix = prefix;
	if (prefix == 0)
		out->mask = 0;
	else
		out->mask = htonl(0xffffffffu << (32 - prefix));
	return 0;
}

static int add_net(uint32_t ip, int prefix)
{
	uint32_t mask;
	int i;

	if (g_net_count >= MAX_NETS)
		return -1;

	if (prefix == 0)
		mask = 0;
	else
		mask = htonl(0xffffffffu << (32 - prefix));

	for (i = 0; i < g_net_count; i++) {
		if (g_nets[i].ip == ip && g_nets[i].prefix == prefix)
			return 0;
	}

	g_nets[g_net_count].ip = ip;
	g_nets[g_net_count].mask = mask;
	g_nets[g_net_count].prefix = prefix;
	g_net_count++;
	return 0;
}

static int ip_in_nets(uint32_t ip)
{
	int i;

	for (i = 0; i < g_net_count; i++) {
		if ((ip & g_nets[i].mask) == (g_nets[i].ip & g_nets[i].mask))
			return 1;
	}
	return 0;
}

static int resolve_ipv4(const char *host, struct in_addr *out)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	int rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
#ifdef MTLS_STATIC_BUILD
	/*
	 * 静态 glibc 解析域名要 dlopen 目标机的 NSS 模块（libnss_dns.so.2 等），
	 * 版本不匹配会失败。静态版本只接受 IP 字面量，配置写错时立即报错。
	 */
	hints.ai_flags |= AI_NUMERICHOST;
#endif

	rc = getaddrinfo(host, NULL, &hints, &res);
	if (rc)
		return -1;

	*out = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
	freeaddrinfo(res);
	return 0;
}

static int is_local_ipv4(uint32_t ip)
{
	struct ifaddrs *ifas = NULL;
	struct ifaddrs *ifa;
	int found = 0;

	if ((ntohl(ip) >> 24) == 127)
		return 1;
	if (getifaddrs(&ifas) != 0)
		return 0;
	for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
			continue;
		if (((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr == ip) {
			found = 1;
			break;
		}
	}
	freeifaddrs(ifas);
	return found;
}

static void format_addr(const struct sockaddr_storage *ss, socklen_t len,
			char *buf, size_t buflen)
{
	char host[INET6_ADDRSTRLEN];
	char serv[16];

	if (getnameinfo((const struct sockaddr *)ss, len, host, sizeof(host),
			serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
		snprintf(buf, buflen, "?");
		return;
	}
	snprintf(buf, buflen, "%s:%s", host, serv);
}

static int set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);

	if (flags < 0)
		return -1;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void set_socket_timeout(int fd, int seconds)
{
	struct timeval tv;

	tv.tv_sec = seconds;
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int cert_common_name(X509 *cert, char *buf, size_t buflen)
{
	const X509_NAME *name;
	const X509_NAME_ENTRY *entry;
	const ASN1_STRING *data;
	unsigned char *utf8 = NULL;
	int idx;
	int len;

	name = X509_get_subject_name(cert);
	if (!name)
		return -1;
	idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
	if (idx < 0)
		return -1;
	entry = X509_NAME_get_entry(name, idx);
	if (!entry)
		return -1;
	data = X509_NAME_ENTRY_get_data(entry);
	if (!data)
		return -1;

	len = ASN1_STRING_to_UTF8(&utf8, data);
	if (len < 0)
		return -1;
	snprintf(buf, buflen, "%.*s", len, utf8);
	OPENSSL_free(utf8);
	return 0;
}

static int verify_client_cert(int preverify_ok, X509_STORE_CTX *store)
{
	X509 *cert;
	char cn[256];
	int depth;
	int i;

	depth = X509_STORE_CTX_get_error_depth(store);
	if (!preverify_ok) {
		cert = X509_STORE_CTX_get_current_cert(store);
		cn[0] = '\0';
		if (cert)
			cert_common_name(cert, cn, sizeof(cn));
		log_error("client certificate rejected at depth %d (cn=%s): %s",
			  depth, cn[0] ? cn : "-",
			  X509_verify_cert_error_string(
				  X509_STORE_CTX_get_error(store)));
		return 0;
	}

	if (depth != 0 || g_allow_cn_count == 0)
		return 1;

	cert = X509_STORE_CTX_get_current_cert(store);
	if (!cert || cert_common_name(cert, cn, sizeof(cn)) != 0) {
		log_error("client certificate has no usable common name");
		return 0;
	}

	for (i = 0; i < g_allow_cn_count; i++) {
		if (strcmp(cn, g_allow_cns[i]) == 0)
			return 1;
	}

	log_error("client certificate cn=%s is not in --allow-cn list", cn);
	return 0;
}

static SSL_CTX *tls_ctx_new(const struct instance_cfg *inst)
{
	SSL_CTX *ctx;
	STACK_OF(X509_NAME) *ca_names;

	OPENSSL_init_ssl(0, NULL);

	ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
		log_error("SSL_CTX_new failed: %s", ssl_error_string());
		return NULL;
	}

	if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
		log_error("failed to set minimum TLS version");
		goto fail;
	}
	SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
	SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
			      SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	if (!SSL_CTX_use_certificate_chain_file(ctx, inst->cert_file)) {
		log_error("cannot load server certificate %s: %s",
			  inst->cert_file, ssl_error_string());
		goto fail;
	}
	if (!SSL_CTX_use_PrivateKey_file(ctx, inst->key_file,
					 SSL_FILETYPE_PEM)) {
		log_error("cannot load private key %s: %s", inst->key_file,
			  ssl_error_string());
		goto fail;
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		log_error("server certificate and key do not match");
		goto fail;
	}
	if (!SSL_CTX_load_verify_locations(ctx, inst->ca_file, NULL)) {
		log_error("cannot load client CA %s: %s", inst->ca_file,
			  ssl_error_string());
		goto fail;
	}

	ca_names = SSL_load_client_CA_file(inst->ca_file);
	if (!ca_names) {
		log_error("cannot build client CA list from %s", inst->ca_file);
		goto fail;
	}
	SSL_CTX_set_client_CA_list(ctx, ca_names);
	SSL_CTX_set_verify(ctx,
			   SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			   verify_client_cert);

	return ctx;

fail:
	SSL_CTX_free(ctx);
	return NULL;
}

/* 父进程在 fork 前统一校验一遍证书，避免子进程反复启动失败 */
static int tls_validate_all(void)
{
	int i;

	for (i = 0; i < g_cfg.count; i++) {
		SSL_CTX *ctx = tls_ctx_new(&g_cfg.inst[i]);

		if (!ctx) {
			log_error("instance #%d certificate check failed", i);
			return -1;
		}
		SSL_CTX_free(ctx);
	}
	return 0;
}

static int tls_init(const struct instance_cfg *inst)
{
	g_tls_ctx = tls_ctx_new(inst);
	return g_tls_ctx ? 0 : -1;
}

static int create_listener(struct instance_cfg *inst)
{
	struct sockaddr_in addr;
	int fd;
	int one = 1;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		log_error("instance #%d: socket: %s", inst->index,
			  strerror(errno));
		return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)inst->listen_port);
	if (inet_pton(AF_INET, g_cfg.listen_host, &addr.sin_addr) != 1) {
		log_error("instance #%d: invalid listen address: %s",
			  inst->index, g_cfg.listen_host);
		close(fd);
		return -1;
	}

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		log_error("instance #%d: bind %s:%d: %s", inst->index,
			  g_cfg.listen_host, inst->listen_port,
			  strerror(errno));
		if (inst->same_port && errno == EADDRINUSE)
			log_error("instance #%d: start mtls_shield before the "
				  "backend so cgroup/bind4 can move the "
				  "backend's bind() to %s:%d",
				  inst->index, inst->upstream.host,
				  inst->upstream.port);
		close(fd);
		return -1;
	}
	if (listen(fd, 256) < 0) {
		log_error("instance #%d: listen: %s", inst->index,
			  strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

static int connect_upstream(const struct instance_cfg *inst)
{
	struct pollfd pfd;
	int fd;
	int err = 0;
	socklen_t errlen = sizeof(err);
	int one = 1;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
#ifdef TCP_KEEPIDLE
	{
		int idle = 60;
		int intvl = 10;
		int cnt = 3;

		setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
		setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl,
			   sizeof(intvl));
		setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
	}
#endif

	if (set_nonblocking(fd) < 0) {
		close(fd);
		return -1;
	}

	if (connect(fd, (struct sockaddr *)&inst->upstream_addr,
		    sizeof(inst->upstream_addr)) < 0) {
		if (errno != EINPROGRESS) {
			close(fd);
			return -1;
		}
		pfd.fd = fd;
		pfd.events = POLLOUT;
		pfd.revents = 0;
		{
			int pr = poll(&pfd, 1, 5000);

			if (pr <= 0) {
				if (pr == 0)
					errno = ETIMEDOUT;
				close(fd);
				return -1;
			}
		}
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

static int upstream_socket_usable(int fd)
{
	char byte;
	ssize_t n;

	do {
		n = recv(fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
	} while (n < 0 && errno == EINTR);

	if (n > 0)
		return 1;
	if (n == 0)
		return 0;
	return errno == EAGAIN || errno == EWOULDBLOCK;
}

static void *upstream_pool_worker(void *opaque)
{
	struct instance_cfg *inst = opaque;
	struct upstream_pool *pool = &inst->pool;
	struct timespec backoff = { .tv_sec = 0, .tv_nsec = 250000000 };

	for (;;) {
		int fd;

		pthread_mutex_lock(&pool->lock);
		while (!pool->stopping && pool->count >= pool->capacity)
			pthread_cond_wait(&pool->cond, &pool->lock);
		if (pool->stopping) {
			pthread_mutex_unlock(&pool->lock);
			break;
		}
		pthread_mutex_unlock(&pool->lock);

		fd = connect_upstream(inst);
		if (fd < 0) {
			nanosleep(&backoff, NULL);
			continue;
		}

		pthread_mutex_lock(&pool->lock);
		if (pool->stopping || pool->count >= pool->capacity) {
			pthread_mutex_unlock(&pool->lock);
			close(fd);
			continue;
		}
		pool->fds[pool->count++] = fd;
		pthread_mutex_unlock(&pool->lock);
	}

	return NULL;
}

static int upstream_pool_get(struct instance_cfg *inst)
{
	struct upstream_pool *pool = &inst->pool;

	for (;;) {
		int fd = -1;
		int capacity;

		pthread_mutex_lock(&pool->lock);
		capacity = pool->capacity;
		if (capacity > 0 && pool->count > 0) {
			fd = pool->fds[--pool->count];
			__atomic_add_fetch(&pool->hits, 1, __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&pool->misses, 1, __ATOMIC_RELAXED);
		}
		pthread_cond_signal(&pool->cond);
		pthread_mutex_unlock(&pool->lock);

		if (capacity == 0 || fd < 0)
			return connect_upstream(inst);
		if (upstream_socket_usable(fd))
			return fd;
		close(fd);
	}
}

static void upstream_pool_discard(int fd)
{
	close(fd);
}

static int upstream_pool_start(struct instance_cfg *inst)
{
	struct upstream_pool *pool = &inst->pool;

	memset(pool, 0, sizeof(*pool));
	pthread_mutex_init(&pool->lock, NULL);
	pthread_cond_init(&pool->cond, NULL);

	if (g_cfg.pool_size <= 0)
		return 0;

	pool->fds = calloc((size_t)g_cfg.pool_size, sizeof(*pool->fds));
	if (!pool->fds)
		return -1;
	pool->capacity = g_cfg.pool_size;

	if (pthread_create(&pool->thread, NULL, upstream_pool_worker,
			   inst) != 0) {
		free(pool->fds);
		pool->fds = NULL;
		pool->capacity = 0;
		return -1;
	}

	pool->running = 1;
	log_info("upstream connection pool: size=%d", pool->capacity);
	return 0;
}

static void upstream_pool_stop(struct instance_cfg *inst)
{
	struct upstream_pool *pool = &inst->pool;
	int i;

	if (!pool->running) {
		pthread_cond_destroy(&pool->cond);
		pthread_mutex_destroy(&pool->lock);
		return;
	}

	pthread_mutex_lock(&pool->lock);
	pool->stopping = 1;
	pthread_cond_broadcast(&pool->cond);
	for (i = 0; i < pool->count; i++)
		close(pool->fds[i]);
	pool->count = 0;
	pthread_mutex_unlock(&pool->lock);

	pthread_join(pool->thread, NULL);

	pthread_mutex_lock(&pool->lock);
	pool->capacity = 0;
	pthread_mutex_unlock(&pool->lock);

	pthread_cond_destroy(&pool->cond);
	pthread_mutex_destroy(&pool->lock);
	free(pool->fds);
	pool->fds = NULL;
	pool->running = 0;
}

static void print_pool_stats(struct instance_cfg *inst)
{
	unsigned long long hits;
	unsigned long long misses;

	if (!inst->pool.running)
		return;

	hits = __atomic_load_n(&inst->pool.hits, __ATOMIC_RELAXED);
	misses = __atomic_load_n(&inst->pool.misses, __ATOMIC_RELAXED);
	log_info("upstream pool: size=%d hits=%llu misses=%llu",
		 inst->pool.capacity, hits, misses);
}

static int relay_loop(SSL *ssl, int cfd, int ufd)
{
	unsigned char *to_up = malloc(RELAY_BUF_SIZE);
	unsigned char *to_cli = malloc(RELAY_BUF_SIZE);
	size_t up_off = 0, up_len = 0;
	size_t cli_off = 0, cli_len = 0;
	int client_eof = 0;
	int upstream_eof = 0;
	int upstream_shut = 0;
	int client_want_write = 0;
	int rc = 0;

	if (!to_up || !to_cli) {
		free(to_up);
		free(to_cli);
		return -1;
	}

	for (;;) {
		struct pollfd pfds[2];
		short cev = 0;
		short uev = 0;
		int pending;
		int n;

		if (g_stop)
			break;

		if (!client_eof && up_len < RELAY_BUF_SIZE)
			cev |= POLLIN;
		if (cli_len > 0 || client_want_write)
			cev |= POLLOUT;
		if (!upstream_eof && cli_len < RELAY_BUF_SIZE)
			uev |= POLLIN;
		if (up_len > 0)
			uev |= POLLOUT;

		pfds[0].fd = cfd;
		pfds[0].events = cev;
		pfds[0].revents = 0;
		pfds[1].fd = ufd;
		pfds[1].events = uev;
		pfds[1].revents = 0;

		pending = SSL_pending(ssl);
		n = poll(pfds, 2, pending > 0 ? 0 : 1000);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			log_error("relay poll: %s", strerror(errno));
			rc = -1;
			break;
		}

		if (pfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
			if (!(pfds[0].revents & POLLIN))
				client_eof = 1;
		}
		if (pfds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
			if (!(pfds[1].revents & POLLIN))
				upstream_eof = 1;
		}

		pending = SSL_pending(ssl);
		if (!client_eof && up_len < RELAY_BUF_SIZE &&
		    (pending > 0 || (pfds[0].revents & POLLIN))) {
			int r = SSL_read(ssl, to_up + up_len,
					 (int)(RELAY_BUF_SIZE - up_len));

			if (r > 0) {
				up_len += (size_t)r;
				client_want_write = 0;
			} else {
				int err = SSL_get_error(ssl, r);

				if (err == SSL_ERROR_WANT_READ) {
					client_want_write = 0;
				} else if (err == SSL_ERROR_WANT_WRITE) {
					client_want_write = 1;
				} else if (err == SSL_ERROR_ZERO_RETURN) {
					client_eof = 1;
				} else {
					log_error("TLS read: %s",
						  ssl_error_string());
					rc = -1;
					break;
				}
			}
		}

		if (!upstream_eof && cli_len < RELAY_BUF_SIZE &&
		    (pfds[1].revents & POLLIN)) {
			ssize_t r = read(ufd, to_cli + cli_len,
					 RELAY_BUF_SIZE - cli_len);

			if (r > 0) {
				cli_len += (size_t)r;
			} else if (r == 0) {
				upstream_eof = 1;
			} else if (errno != EAGAIN && errno != EINTR) {
				log_error("backend read: %s", strerror(errno));
				rc = -1;
				break;
			}
		}

		if (up_len > 0) {
			ssize_t w = write(ufd, to_up + up_off, up_len - up_off);

			if (w > 0) {
				up_off += (size_t)w;
				if (up_off == up_len)
					up_off = up_len = 0;
			} else if (w < 0 && errno != EAGAIN && errno != EINTR) {
				log_error("backend write: %s", strerror(errno));
				rc = -1;
				break;
			}
		}

		if (cli_len > 0) {
			int w = SSL_write(ssl, to_cli + cli_off,
					  (int)(cli_len - cli_off));

			if (w > 0) {
				cli_off += (size_t)w;
				if (cli_off == cli_len)
					cli_off = cli_len = 0;
				client_want_write = 0;
			} else {
				int err = SSL_get_error(ssl, w);

				if (err == SSL_ERROR_WANT_WRITE) {
					client_want_write = 1;
				} else if (err == SSL_ERROR_WANT_READ) {
					client_want_write = 0;
				} else {
					log_error("TLS write: %s",
						  ssl_error_string());
					rc = -1;
					break;
				}
			}
		}

		if (client_eof && up_len == 0 && !upstream_shut) {
			shutdown(ufd, SHUT_WR);
			upstream_shut = 1;
		}
		if (upstream_eof && cli_len == 0)
			break;
		if (client_eof && upstream_eof && up_len == 0 && cli_len == 0)
			break;
	}

	free(to_up);
	free(to_cli);
	return rc;
}

static void *conn_thread(void *opaque)
{
	struct conn_arg *arg = opaque;
	struct instance_cfg *inst = arg->inst;
	SSL *ssl = NULL;
	X509 *cert = NULL;
	char cn[256] = "-";
	char local_str[INET6_ADDRSTRLEN + 16] = "?";
	struct sockaddr_storage local;
	socklen_t local_len = sizeof(local);
	int ufd = -1;
	int fd = arg->fd;

	ssl = SSL_new(g_tls_ctx);
	if (!ssl) {
		log_error("SSL_new failed: %s", ssl_error_string());
		goto out;
	}
	if (getsockname(fd, (struct sockaddr *)&local, &local_len) == 0)
		format_addr(&local, local_len, local_str, sizeof(local_str));

	set_socket_timeout(fd, g_cfg.handshake_timeout);
	SSL_set_fd(ssl, fd);
	if (SSL_accept(ssl) <= 0) {
		long verify = SSL_get_verify_result(ssl);

		if (verify != X509_V_OK)
			log_error("TLS handshake from %s failed: %s",
				  arg->peer_str,
				  X509_verify_cert_error_string(verify));
		else
			log_error("TLS handshake from %s failed: %s",
				  arg->peer_str, ssl_error_string());
		goto out;
	}

	set_socket_timeout(fd, 0);
	if (set_nonblocking(fd) < 0) {
		log_error("cannot set client socket nonblocking: %s",
			  strerror(errno));
		goto out;
	}

	cert = SSL_get1_peer_certificate(ssl);
	if (cert && cert_common_name(cert, cn, sizeof(cn)) != 0)
		snprintf(cn, sizeof(cn), "-");
	if (cert) {
		X509_free(cert);
		cert = NULL;
	}

	ufd = upstream_pool_get(inst);
	if (ufd < 0) {
		log_error("cannot connect upstream %s:%d for client %s: %s",
			  inst->upstream.host, inst->upstream.port,
			  arg->peer_str, strerror(errno));
		goto out;
	}

	log_info("mTLS ok client=%s cn=%s local=%s upstream=%s:%d",
		 arg->peer_str, cn, local_str, inst->upstream.host,
		 inst->upstream.port);

	relay_loop(ssl, fd, ufd);

out:
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	if (ufd >= 0)
		upstream_pool_discard(ufd);
	close(fd);
	__atomic_sub_fetch(&inst->active_conns, 1, __ATOMIC_SEQ_CST);
	free(arg);
	return NULL;
}

static int bpf_stats_fd(void)
{
	return bpf_map__fd(g_skel->maps.stats);
}

static void print_bpf_stats(void)
{
	static const char *names[] = {
		"sk_lookup_redirect",
		"connect_redirect",
		"no_proxy_socket",
		"assign_error",
		"sk_lookup_seen",
		"port_match",
		"bind_redirect",
	};
	uint64_t total[7] = { 0 };
	int ncpu;
	uint64_t *values;
	uint32_t key;
	int i;
	int fd;

	if (!g_skel)
		return;
	ncpu = libbpf_num_possible_cpus();
	if (ncpu <= 0)
		return;

	values = calloc((size_t)ncpu, sizeof(*values));
	if (!values)
		return;

	fd = bpf_stats_fd();
	for (key = 0; key < 7; key++) {
		if (bpf_map_lookup_elem(fd, &key, values) != 0)
			continue;
		for (i = 0; i < ncpu; i++)
			total[key] += values[i];
	}

	log_info("bpf stats: %s=%llu %s=%llu %s=%llu %s=%llu "
		 "%s=%llu %s=%llu %s=%llu",
		 names[0], (unsigned long long)total[0],
		 names[1], (unsigned long long)total[1],
		 names[2], (unsigned long long)total[2],
		 names[3], (unsigned long long)total[3],
		 names[4], (unsigned long long)total[4],
		 names[5], (unsigned long long)total[5],
		 names[6], (unsigned long long)total[6]);
	free(values);
}

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

static int any_same_port(void)
{
	int i;

	for (i = 0; i < g_cfg.count; i++) {
		if (g_cfg.inst[i].same_port)
			return 1;
	}
	return 0;
}

static int any_redirect_mode(void)
{
	int i;

	for (i = 0; i < g_cfg.count; i++) {
		if (!g_cfg.inst[i].same_port)
			return 1;
	}
	return 0;
}

static int bpf_load(void)
{
	g_skel = mtls_shield_bpf__open();
	if (!g_skel) {
		log_error("cannot open BPF skeleton: %s", strerror(errno));
		return -1;
	}

	if (mtls_shield_bpf__load(g_skel)) {
		log_error("cannot load BPF programs: %s", strerror(errno));
		return -1;
	}
	return 0;
}

static int bpf_configure(void)
{
	uint32_t key;
	int map_fd;
	int i;

	map_fd = bpf_map__fd(g_skel->maps.shield_cfg_map);
	if (map_fd < 0) {
		log_error("cannot get shield config map fd");
		return -1;
	}

	for (i = 0; i < g_cfg.count; i++) {
		struct instance_cfg *inst = &g_cfg.inst[i];
		struct shield_port_cfg cfg;

		memset(&cfg, 0, sizeof(cfg));
		cfg.enabled = 1;
		cfg.proxy_port = htons((uint16_t)inst->listen_port);
		if (inst->same_port) {
			cfg.mode = SHIELD_MODE_SAME_PORT;
			cfg.backend_ip4 = inst->upstream_addr.sin_addr.s_addr;
			cfg.backend_port = htons((uint16_t)inst->upstream.port);
		} else {
			cfg.mode = SHIELD_MODE_REDIRECT;
		}

		key = (uint32_t)inst->protect_port;
		if (bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY) != 0) {
			log_error("cannot write shield config for tcp/%d: %s",
				  inst->protect_port, strerror(errno));
			return -1;
		}
	}

	if (any_redirect_mode()) {
		map_fd = bpf_map__fd(g_skel->maps.protect_nets);
		for (i = 0; i < g_net_count; i++) {
			struct lpm_key net_key;
			uint32_t enabled = 1;

			net_key.prefixlen = (uint32_t)g_nets[i].prefix;
			net_key.ip = g_nets[i].ip;
			if (bpf_map_update_elem(map_fd, &net_key, &enabled,
						BPF_ANY) != 0) {
				log_error("cannot add protected network: %s",
					  strerror(errno));
				return -1;
			}
		}

		/* redirect 模式下每个原端口对应自己的代理监听 socket */
		map_fd = bpf_map__fd(g_skel->maps.proxy_socks);
		for (i = 0; i < g_cfg.count; i++) {
			struct instance_cfg *inst = &g_cfg.inst[i];

			if (inst->same_port)
				continue;
			key = (uint32_t)inst->protect_port;
			if (bpf_map_update_elem(map_fd, &key,
						&inst->listen_fd,
						BPF_ANY) != 0) {
				log_error("cannot publish proxy socket for "
					  "tcp/%d: %s", inst->protect_port,
					  strerror(errno));
				return -1;
			}
		}
	}

	return 0;
}

static int bpf_attach(void)
{
	int netns_fd;

	if (any_same_port()) {
		g_bind_link = attach_cgroup_prog(g_skel->progs.shield_bind4,
						 "/sys/fs/cgroup");
		if (!g_bind_link) {
			log_error("cannot attach cgroup/bind4: %s",
				  strerror(errno));
			return -1;
		}
		log_info("attached cgroup/bind4 for same-port instances");
	}

	if (any_redirect_mode()) {
		netns_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
		if (netns_fd < 0) {
			log_error("cannot open current netns: %s",
				  strerror(errno));
			return -1;
		}
		g_sk_link = bpf_program__attach_netns(
			g_skel->progs.shield_sk_lookup, netns_fd);
		close(netns_fd);
		if (!g_sk_link) {
			log_error("cannot attach sk_lookup program: %s",
				  strerror(errno));
			return -1;
		}
		log_info("attached sk_lookup to current network namespace");

		if (g_cfg.local_redirect) {
			g_cg_link = attach_cgroup_prog(
				g_skel->progs.shield_connect4, "/sys/fs/cgroup");
			if (g_cg_link)
				log_info("attached cgroup/connect4 to "
					 "/sys/fs/cgroup");
			else
				log_warn("cgroup/connect4 not attached (%s); "
					 "local clients may bypass redirect",
					 strerror(errno));
		}
	}

	return 0;
}

static int upstream_excluded_from_nets(const struct instance_cfg *inst,
				       uint32_t ip)
{
	if (inst->same_port)
		return 0;
	if (inst->upstream.port != inst->protect_port)
		return 0;
	return inst->upstream_addr.sin_addr.s_addr == ip;
}

static int prepare_nets(void)
{
	struct ifaddrs *ifas = NULL;
	struct ifaddrs *ifa;
	int i;
	int j;

	if (g_net_count == 0) {
		if (getifaddrs(&ifas) != 0) {
			log_error("getifaddrs: %s", strerror(errno));
			return -1;
		}
		for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
			uint32_t ip;
			int skip = 0;

			if (!ifa->ifa_addr ||
			    ifa->ifa_addr->sa_family != AF_INET)
				continue;
			ip = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
			if (ip == 0)
				continue;
			for (j = 0; j < g_cfg.count; j++) {
				if (upstream_excluded_from_nets(&g_cfg.inst[j],
								ip)) {
					skip = 1;
					break;
				}
			}
			if (!skip)
				add_net(ip, 32);
		}
		freeifaddrs(ifas);
	}

	if (g_net_count == 0)
		add_net(htonl(INADDR_LOOPBACK), 32);

	for (i = 0; i < g_net_count; i++) {
		char ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &g_nets[i].ip, ip, sizeof(ip));
		log_info("protected network: %s/%d", ip, g_nets[i].prefix);
	}

	for (i = 0; i < g_cfg.count; i++) {
		struct instance_cfg *inst = &g_cfg.inst[i];

		if (inst->same_port || inst->upstream.port != inst->protect_port)
			continue;
		if (ip_in_nets(inst->upstream_addr.sin_addr.s_addr)) {
			log_error("instance #%d: upstream %s:%d is inside a "
				  "protected network; the proxy would loop "
				  "into itself. Use a different upstream "
				  "port or protected CIDR.",
				  i, inst->upstream.host,
				  inst->upstream.port);
			return -1;
		}
	}

	return 0;
}

static void on_signal(int sig)
{
	if (sig == SIGUSR1)
		g_want_stats = 1;
	else if (sig == SIGCHLD)
		g_child_event = 1;
	else
		g_stop = 1;
}

static void install_parent_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGCHLD, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);
}

static void install_child_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	signal(SIGCHLD, SIG_DFL);
	signal(SIGPIPE, SIG_IGN);
}

static int wait_for_connections(struct instance_cfg *inst, int timeout_ms)
{
	int waited = 0;

	while (__atomic_load_n(&inst->active_conns, __ATOMIC_SEQ_CST) > 0) {
		if (waited >= timeout_ms)
			return -1;
		usleep(10000);
		waited += 10;
	}
	return 0;
}

static void accept_loop(struct instance_cfg *inst)
{
	while (!g_stop) {
		struct pollfd pfd;
		struct sockaddr_storage peer;
		socklen_t peer_len;
		struct conn_arg *arg;
		pthread_t thread;
		int fd;
		int rc;
		int active;

		if (g_want_stats) {
			g_want_stats = 0;
			print_pool_stats(inst);
		}

		pfd.fd = inst->listen_fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		rc = poll(&pfd, 1, 500);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			log_error("accept poll: %s", strerror(errno));
			break;
		}
		if (rc == 0 || !(pfd.revents & POLLIN))
			continue;

		peer_len = sizeof(peer);
		fd = accept4(inst->listen_fd, (struct sockaddr *)&peer,
			     &peer_len, SOCK_CLOEXEC);
		if (fd < 0) {
			if (errno == EINTR || errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				continue;
			log_error("accept: %s", strerror(errno));
			continue;
		}

		active = __atomic_add_fetch(&inst->active_conns, 1,
					    __ATOMIC_SEQ_CST);
		if (active > g_cfg.max_conns) {
			__atomic_sub_fetch(&inst->active_conns, 1,
					   __ATOMIC_SEQ_CST);
			log_warn("connection limit reached (%d), rejecting",
				 g_cfg.max_conns);
			close(fd);
			continue;
		}

		arg = calloc(1, sizeof(*arg));
		if (!arg) {
			close(fd);
			__atomic_sub_fetch(&inst->active_conns, 1,
					   __ATOMIC_SEQ_CST);
			continue;
		}
		arg->inst = inst;
		arg->fd = fd;
		arg->peer = peer;
		arg->peer_len = peer_len;
		format_addr(&peer, peer_len, arg->peer_str,
			    sizeof(arg->peer_str));

		if (pthread_create(&thread, NULL, conn_thread, arg) != 0) {
			log_error("pthread_create: %s", strerror(errno));
			close(fd);
			free(arg);
			__atomic_sub_fetch(&inst->active_conns, 1,
					   __ATOMIC_SEQ_CST);
			continue;
		}
		pthread_detach(thread);
	}
}

static int worker_run(int idx)
{
	struct instance_cfg *inst = &g_cfg.inst[idx];
	int j;
	int rc = EXIT_FAILURE;

	g_inst = inst;
	snprintf(g_tag_buf, sizeof(g_tag_buf), "w%d:%d", idx,
		 inst->listen_port);
	g_tag = g_tag_buf;

	/* 父进程异常退出时让子进程一起退出，避免留下孤儿转发进程 */
	prctl(PR_SET_PDEATHSIG, SIGTERM);
	if (getppid() == 1)
		_exit(EXIT_FAILURE);

	install_child_signals();

	/* 子进程只保留自己的监听 socket，其他实例的 fd 由父进程继续持有 */
	for (j = 0; j < g_cfg.count; j++) {
		if (j == idx)
			continue;
		if (g_cfg.inst[j].listen_fd >= 0) {
			close(g_cfg.inst[j].listen_fd);
			g_cfg.inst[j].listen_fd = -1;
		}
	}

	/* fork 之后重新取一次随机数，避免父子进程共享 DRBG 状态 */
	RAND_poll();

	if (tls_init(inst) != 0)
		goto out;

	if (g_inst->same_port)
		log_info("ready: mTLS on original tcp/%d (%s:%d); eBPF "
			 "moves the backend's bind() to %s:%d",
			 inst->protect_port, g_cfg.listen_host,
			 inst->listen_port, inst->upstream.host,
			 inst->upstream.port);
	else
		log_info("ready: tcp/%d redirected via eBPF to mTLS %s:%d, "
			 "upstream %s:%d",
			 inst->protect_port, g_cfg.listen_host,
			 inst->listen_port, inst->upstream.host,
			 inst->upstream.port);

	if (upstream_pool_start(inst) != 0)
		log_warn("cannot start upstream connection pool; "
			 "falling back to direct connects");

	accept_loop(inst);
	print_pool_stats(inst);

	if (wait_for_connections(inst, (g_cfg.handshake_timeout + 5) * 1000) == 0)
		upstream_pool_stop(inst);
	else
		log_warn("connections still active at shutdown; "
			 "skipping upstream pool cleanup");

	rc = EXIT_SUCCESS;

out:
	if (g_tls_ctx) {
		SSL_CTX_free(g_tls_ctx);
		g_tls_ctx = NULL;
	}
	if (inst->listen_fd >= 0) {
		close(inst->listen_fd);
		inst->listen_fd = -1;
	}
	return rc;
}

static int find_instance_by_pid(pid_t pid)
{
	int i;

	for (i = 0; i < g_cfg.count; i++) {
		if (g_cfg.inst[i].pid == pid)
			return i;
	}
	return -1;
}

static void describe_status(int status, char *buf, size_t buflen)
{
	if (WIFEXITED(status))
		snprintf(buf, buflen, "exit %d", WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		snprintf(buf, buflen, "signal %d", WTERMSIG(status));
	else
		snprintf(buf, buflen, "status 0x%x", status);
}

static void reap_children(void)
{
	/* 先清标志：清空之后新到的 SIGCHLD 会重新置位，不会丢事件 */
	g_child_event = 0;

	for (;;) {
		int status;
		pid_t pid = waitpid(-1, &status, WNOHANG);
		struct instance_cfg *inst;
		char st[64];
		long long uptime;
		int delay;
		int idx;

		if (pid <= 0)
			break;

		idx = find_instance_by_pid(pid);
		if (idx < 0)
			continue;

		inst = &g_cfg.inst[idx];
		inst->pid = 0;
		if (g_stop)
			continue;

		describe_status(status, st, sizeof(st));
		uptime = now_ms() - inst->started_at_ms;
		if (uptime < 3000) {
			delay = inst->restart_delay > 0 ?
					inst->restart_delay * 2 : 1;
			if (delay > 30)
				delay = 30;
		} else {
			delay = 1;
		}
		inst->restart_delay = delay;
		inst->restart_at_ms = now_ms() + (long long)delay * 1000;
		log_warn("worker #%d pid=%d exited (%s); restart in %ds",
			 idx, (int)pid, st, delay);
	}
}

static int spawn_worker(int idx)
{
	struct instance_cfg *inst = &g_cfg.inst[idx];
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		log_error("fork worker #%d: %s", idx, strerror(errno));
		return -1;
	}
	if (pid == 0) {
		int rc = worker_run(idx);

		_exit(rc);
	}

	inst->pid = pid;
	inst->started_at_ms = now_ms();
	inst->restart_at_ms = 0;
	log_info("worker #%d started pid=%d: listen tcp/%d, protect tcp/%d, "
		 "upstream %s:%d, mode=%s",
		 idx, (int)pid, inst->listen_port, inst->protect_port,
		 inst->upstream.host, inst->upstream.port,
		 inst->same_port ? "same-port" : "redirect");
	return 0;
}

static void schedule_restarts(void)
{
	long long now = now_ms();
	int i;

	if (g_stop)
		return;

	for (i = 0; i < g_cfg.count; i++) {
		struct instance_cfg *inst = &g_cfg.inst[i];

		if (inst->pid > 0 || now < inst->restart_at_ms)
			continue;
		if (spawn_worker(i) != 0) {
			int delay = inst->restart_delay > 0 ?
					inst->restart_delay * 2 : 1;

			if (delay > 30)
				delay = 30;
			inst->restart_delay = delay;
			inst->restart_at_ms = now + (long long)delay * 1000;
			log_error("cannot restart worker #%d; retry in %ds",
				  i, delay);
		}
	}
}

static void forward_stats_request(void)
{
	int i;

	for (i = 0; i < g_cfg.count; i++) {
		if (g_cfg.inst[i].pid > 0)
			kill(g_cfg.inst[i].pid, SIGUSR1);
	}
}

static void print_workers(void)
{
	int i;

	for (i = 0; i < g_cfg.count; i++) {
		struct instance_cfg *inst = &g_cfg.inst[i];

		log_info("#%d listen=tcp/%d protect=tcp/%d upstream=%s:%d "
			 "mode=%s pid=%d state=%s",
			 i, inst->listen_port, inst->protect_port,
			 inst->upstream.host, inst->upstream.port,
			 inst->same_port ? "same-port" : "redirect",
			 (int)inst->pid, inst->pid > 0 ? "running" : "pending");
	}
}

static void supervise(void)
{
	while (!g_stop) {
		if (g_want_stats) {
			g_want_stats = 0;
			print_bpf_stats();
			print_workers();
			forward_stats_request();
		}
		if (g_child_event)
			reap_children();
		schedule_restarts();
		if (g_stop)
			break;
		usleep(200000);
	}
}

static void stop_workers(void)
{
	int i;
	int alive;
	long long deadline;

	g_stop = 1;
	for (i = 0; i < g_cfg.count; i++) {
		if (g_cfg.inst[i].pid > 0)
			kill(g_cfg.inst[i].pid, SIGTERM);
	}

	deadline = now_ms() + (long long)(g_cfg.handshake_timeout + 10) * 1000;
	for (;;) {
		reap_children();
		alive = 0;
		for (i = 0; i < g_cfg.count; i++) {
			if (g_cfg.inst[i].pid > 0)
				alive++;
		}
		if (!alive)
			break;
		if (now_ms() >= deadline) {
			for (i = 0; i < g_cfg.count; i++) {
				if (g_cfg.inst[i].pid > 0) {
					log_warn("worker #%d did not stop in "
						 "time; killing pid=%d", i,
						 (int)g_cfg.inst[i].pid);
					kill(g_cfg.inst[i].pid, SIGKILL);
					waitpid(g_cfg.inst[i].pid, NULL, 0);
					g_cfg.inst[i].pid = 0;
				}
			}
			break;
		}
		usleep(50000);
	}

	/* 收掉可能残留的僵尸 */
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
	for (i = 0; i < g_cfg.count; i++)
		g_cfg.inst[i].pid = 0;
}

static int build_instances(void)
{
	int n = g_listen_count;
	int i;
	int j;

	if (n <= 0) {
		log_error("--listenport is required");
		return -1;
	}
	if (n > MAX_INSTANCES) {
		log_error("too many listen ports (max %d)", MAX_INSTANCES);
		return -1;
	}
	if (g_upstream_count != n) {
		log_error("--upstream needs %d entries (one per listen port), "
			  "got %d", n, g_upstream_count);
		return -1;
	}
	if (g_protect_count && g_protect_count != n) {
		log_error("--protect_port needs %d entries (or omit it to reuse "
			  "--listenport)", n);
		return -1;
	}
	if (g_ca_count && g_ca_count != 1 && g_ca_count != n) {
		log_error("--ca needs 1 or %d entries", n);
		return -1;
	}
	if (g_cert_count && g_cert_count != 1 && g_cert_count != n) {
		log_error("--cert needs 1 or %d entries", n);
		return -1;
	}
	if (g_key_count && g_key_count != 1 && g_key_count != n) {
		log_error("--key needs 1 or %d entries", n);
		return -1;
	}

	memset(g_cfg.inst, 0, sizeof(g_cfg.inst));
	g_cfg.count = n;

	for (i = 0; i < n; i++) {
		struct instance_cfg *inst = &g_cfg.inst[i];
		const char *protect_item = NULL;

		inst->index = i;
		inst->listen_fd = -1;

		if (parse_int(g_listen_items[i], 1, 65535,
			      &inst->listen_port)) {
			log_error("bad --listenport value: %s",
				  g_listen_items[i]);
			return -1;
		}

		if (g_protect_count == 0) {
			inst->protect_port = inst->listen_port;
		} else {
			protect_item = g_protect_items[i];
			if (parse_int(protect_item, 1, 65535,
				      &inst->protect_port)) {
				log_error("bad --protect_port value: %s",
					  protect_item);
				return -1;
			}
		}

		if (parse_endpoint(g_upstream_items[i], &inst->upstream)) {
			log_error("bad --upstream value: %s",
				  g_upstream_items[i]);
			return -1;
		}

		inst->ca_file = g_ca_count ?
			(g_ca_count == 1 ? g_ca_items[0] : g_ca_items[i]) :
			"certs/ca.crt";
		inst->cert_file = g_cert_count ?
			(g_cert_count == 1 ? g_cert_items[0] : g_cert_items[i]) :
			"certs/server.crt";
		inst->key_file = g_key_count ?
			(g_key_count == 1 ? g_key_items[0] : g_key_items[i]) :
			"certs/server.key";

		if (resolve_ipv4(inst->upstream.host,
				 &inst->upstream_addr.sin_addr) != 0) {
			log_error("instance #%d: cannot resolve upstream host "
				  "%s", i, inst->upstream.host);
			return -1;
		}
		inst->upstream_addr.sin_family = AF_INET;
		inst->upstream_addr.sin_port =
			htons((uint16_t)inst->upstream.port);

		inst->same_port = inst->listen_port == inst->protect_port;

		if (inst->same_port &&
		    inst->upstream.port == inst->protect_port) {
			log_error("instance #%d: same-port mode needs an "
				  "internal backend port; --upstream must not "
				  "use tcp/%d", i, inst->protect_port);
			return -1;
		}
		if (inst->same_port &&
		    !is_local_ipv4(inst->upstream_addr.sin_addr.s_addr)) {
			log_error("instance #%d: same-port mode requires "
				  "--upstream to be a local address so the "
				  "backend bind() can be moved there", i);
			return -1;
		}

		for (j = 0; j < i; j++) {
			if (g_cfg.inst[j].listen_port == inst->listen_port) {
				log_error("duplicate listen port tcp/%d",
					  inst->listen_port);
				return -1;
			}
			if (g_cfg.inst[j].protect_port ==
			    inst->protect_port) {
				log_error("duplicate protect port tcp/%d",
					  inst->protect_port);
				return -1;
			}
		}
	}

	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --listenport P1[,P2...] --upstream H1:P1[,H2:P2...] [options]\n"
		"\n"
		"List arguments are matched by index: item N of --listenport,\n"
		"--protect_port, --upstream, --ca, --cert and --key all belong to\n"
		"the same forwarding instance. One value for --ca/--cert/--key is\n"
		"broadcast to every instance; --protect_port, when given, must have\n"
		"one entry per instance.\n"
		"\n"
		"  -l, --listenport LIST       mTLS listen ports, comma separated\n"
		"  -p, --protect_port LIST     original TCP ports (default: = --listenport)\n"
		"  -u, --upstream LIST         plain upstream ADDR:PORT per index\n"
		"  -H, --listen-host ADDR      listen address (default 0.0.0.0)\n"
		"  -n, --protect-cidr CIDR     redirect mode: IP/CIDR to intercept\n"
		"  -a, --ca LIST               client CA bundle per index\n"
		"                              (default certs/ca.crt)\n"
		"  -c, --cert LIST             server certificate per index\n"
		"                              (default certs/server.crt)\n"
		"  -k, --key LIST              server private key per index\n"
		"                              (default certs/server.key)\n"
		"  -C, --allow-cn CN           allowed client cert CN; repeatable\n"
		"  -t, --handshake-timeout SEC TLS handshake timeout (default 10)\n"
		"  -m, --max-conns N           per-process concurrent limit (default 512)\n"
		"  -P, --pool-size N           per-process upstream pool (default 32, 0=off)\n"
		"  -L, --no-local-redirect     skip cgroup/connect4 attach\n"
		"  -v, --verbose               verbose logging\n"
		"  -h, --help                  show this help\n"
		"\n"
		"The main process loads eBPF once, opens all listen sockets and\n"
		"forks one forwarding process per port. It supervises and restarts\n"
		"children that exit unexpectedly.\n"
		"\n"
		"Same-port mode is used when a listen port equals its protect port:\n"
		"eBPF bind4 rewrites the backend's bind() to --upstream, so the\n"
		"backend keeps its original configuration. Start mtls_shield before\n"
		"the backend. If a listen port differs from its protect port, that\n"
		"instance uses the redirect mode (sk_lookup + cgroup/connect4).\n"
		"\n"
		"Example:\n"
		"  %s --listenport 9000,9443 \\\n"
		"      --protect_port 9000,9443 \\\n"
		"      --upstream 127.0.0.1:19000,127.0.0.1:19443 \\\n"
		"      --ca certs/ca.crt --cert certs/server.crt \\\n"
		"      --key certs/server.key\n",
		prog, prog);
}

/*
 * 允许 -listenport=9000,9001 这种单横线长参数写法：
 * getopt_long 只认 --，这里先做一次规范化。
 */
static int normalize_argv(int *argc, char **argv)
{
	static const char *names[] = {
		"listenport", "listen-port", "protect_port", "protect-port",
		"upstream", "listen-host", "protect-cidr", "ca", "cert",
		"key", "allow-cn", "handshake-timeout", "max-conns",
		"pool-size", "no-local-redirect", "verbose", "help",
	};
	int i;

	for (i = 1; i < *argc; i++) {
		char *arg = argv[i];
		char *eq;
		size_t namelen;
		size_t k;
		int match = 0;

		if (arg[0] != '-' || arg[1] == '-' || arg[1] == '\0')
			continue;

		eq = strchr(arg + 1, '=');
		namelen = eq ? (size_t)(eq - (arg + 1)) : strlen(arg + 1);
		if (namelen < 2)
			continue;

		for (k = 0; k < sizeof(names) / sizeof(names[0]); k++) {
			if (strlen(names[k]) == namelen &&
			    strncmp(arg + 1, names[k], namelen) == 0) {
				match = 1;
				break;
			}
		}
		if (!match)
			continue;

		{
			size_t len = strlen(arg);
			char *fixed = malloc(len + 2);

			if (!fixed)
				return -1;
			fixed[0] = '-';
			memcpy(fixed + 1, arg, len + 1);
			argv[i] = fixed;
		}
	}
	return 0;
}

static int parse_args(int argc, char **argv)
{
	static const struct option options[] = {
		{ "listenport", required_argument, NULL, 'l' },
		{ "listen-port", required_argument, NULL, 'l' },
		{ "protect_port", required_argument, NULL, 'p' },
		{ "protect-port", required_argument, NULL, 'p' },
		{ "upstream", required_argument, NULL, 'u' },
		{ "listen-host", required_argument, NULL, 'H' },
		{ "protect-cidr", required_argument, NULL, 'n' },
		{ "ca", required_argument, NULL, 'a' },
		{ "cert", required_argument, NULL, 'c' },
		{ "key", required_argument, NULL, 'k' },
		{ "allow-cn", required_argument, NULL, 'C' },
		{ "handshake-timeout", required_argument, NULL, 't' },
		{ "max-conns", required_argument, NULL, 'm' },
		{ "pool-size", required_argument, NULL, 'P' },
		{ "no-local-redirect", no_argument, NULL, 'L' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	int opt;

	while ((opt = getopt_long(argc, argv, "l:p:u:H:n:a:c:k:C:t:m:P:Lvh",
				  options, NULL)) != -1) {
		switch (opt) {
		case 'l':
			if (parse_list_option(optarg, g_listen_items,
					      &g_listen_count, MAX_INSTANCES,
					      "--listenport"))
				return -1;
			break;
		case 'p':
			if (parse_list_option(optarg, g_protect_items,
					      &g_protect_count, MAX_INSTANCES,
					      "--protect_port"))
				return -1;
			break;
		case 'u':
			if (parse_list_option(optarg, g_upstream_items,
					      &g_upstream_count, MAX_INSTANCES,
					      "--upstream"))
				return -1;
			break;
		case 'H':
			snprintf(g_cfg.listen_host, sizeof(g_cfg.listen_host),
				 "%s", optarg);
			break;
		case 'n': {
			struct net_cidr net;

			if (parse_cidr(optarg, &net)) {
				log_error("bad --protect-cidr value: %s",
					  optarg);
				return -1;
			}
			if (add_net(net.ip, net.prefix)) {
				log_error("too many protected networks");
				return -1;
			}
			break;
		}
		case 'a':
			if (parse_list_option(optarg, g_ca_items, &g_ca_count,
					      MAX_INSTANCES, "--ca"))
				return -1;
			break;
		case 'c':
			if (parse_list_option(optarg, g_cert_items,
					      &g_cert_count, MAX_INSTANCES,
					      "--cert"))
				return -1;
			break;
		case 'k':
			if (parse_list_option(optarg, g_key_items, &g_key_count,
					      MAX_INSTANCES, "--key"))
				return -1;
			break;
		case 'C':
			if (g_allow_cn_count >= MAX_ALLOW_CN) {
				log_error("too many --allow-cn values");
				return -1;
			}
			g_allow_cns[g_allow_cn_count++] = optarg;
			break;
		case 't':
			if (parse_int(optarg, 1, 300,
				      &g_cfg.handshake_timeout)) {
				log_error("bad --handshake-timeout value: %s",
					  optarg);
				return -1;
			}
			break;
		case 'm':
			if (parse_int(optarg, 1, 100000, &g_cfg.max_conns)) {
				log_error("bad --max-conns value: %s", optarg);
				return -1;
			}
			break;
		case 'P':
			if (parse_int(optarg, 0, 4096, &g_cfg.pool_size)) {
				log_error("bad --pool-size value: %s", optarg);
				return -1;
			}
			break;
		case 'L':
			g_cfg.local_redirect = 0;
			break;
		case 'v':
			g_cfg.verbose = 1;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			usage(argv[0]);
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	int rc = EXIT_FAILURE;
	int i;

	if (normalize_argv(&argc, argv) != 0) {
		log_error("out of memory");
		return EXIT_FAILURE;
	}
	if (parse_args(argc, argv) != 0)
		return EXIT_FAILURE;

	libbpf_set_print(libbpf_print_fn);

	if (geteuid() != 0)
		log_warn("not running as root; BPF load may fail");

	if (build_instances() != 0)
		return EXIT_FAILURE;

	if (tls_validate_all() != 0)
		return EXIT_FAILURE;

	if (any_redirect_mode()) {
		if (g_net_count > 0)
			log_info("--protect-cidr overrides auto-detected "
				 "protected networks");
		if (prepare_nets() != 0)
			return EXIT_FAILURE;
	} else if (g_net_count > 0) {
		log_warn("--protect-cidr is ignored: no redirect-mode instance");
	}

	if (bpf_load() != 0)
		goto out;

	/*
	 * 先 bind 所有监听端口，再挂 bind4。否则子进程/父进程自己的
	 * bind(原端口) 也会被 rewrite 到内部端口。
	 */
	for (i = 0; i < g_cfg.count; i++) {
		g_cfg.inst[i].listen_fd = create_listener(&g_cfg.inst[i]);
		if (g_cfg.inst[i].listen_fd < 0)
			goto out;
	}

	if (bpf_configure() != 0)
		goto out;
	if (bpf_attach() != 0)
		goto out;

	install_parent_signals();

	log_info("daemon ready: %d instance(s)", g_cfg.count);
	print_workers();

	for (i = 0; i < g_cfg.count; i++) {
		if (spawn_worker(i) != 0) {
			log_error("cannot start forwarding process for "
				  "instance #%d", i);
			g_stop = 1;
			stop_workers();
			goto out;
		}
	}

	supervise();
	stop_workers();
	print_bpf_stats();
	log_info("all forwarding processes stopped");
	rc = EXIT_SUCCESS;

out:
	if (g_bind_link) {
		bpf_link__destroy(g_bind_link);
		g_bind_link = NULL;
	}
	if (g_cg_link) {
		bpf_link__destroy(g_cg_link);
		g_cg_link = NULL;
	}
	if (g_sk_link) {
		bpf_link__destroy(g_sk_link);
		g_sk_link = NULL;
	}
	if (g_skel) {
		mtls_shield_bpf__destroy(g_skel);
		g_skel = NULL;
	}
	for (i = 0; i < g_cfg.count; i++) {
		if (g_cfg.inst[i].listen_fd >= 0) {
			close(g_cfg.inst[i].listen_fd);
			g_cfg.inst[i].listen_fd = -1;
		}
	}
	return rc;
}
