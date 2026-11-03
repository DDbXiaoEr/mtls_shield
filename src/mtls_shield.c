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
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "mtls_shield.skel.h"

#define MAX_NETS 128
#define MAX_ALLOW_CN 16
#define RELAY_BUF_SIZE 65536

struct endpoint {
	char host[256];
	int port;
};

struct app_config {
	struct endpoint listen;
	struct endpoint upstream;
	int protect_port;
	const char *ca_file;
	const char *cert_file;
	const char *key_file;
	int handshake_timeout;
	int max_conns;
	int pool_size;
	int local_redirect;
	int verbose;
};

struct net_cidr {
	uint32_t ip;
	uint32_t mask;
	int prefix;
};

struct shield_cfg {
	uint32_t enabled;
	uint32_t backend_ip4;
	uint16_t protect_port;
	uint16_t proxy_port;
	uint16_t backend_port;
	uint16_t reserved;
};

struct lpm_key {
	uint32_t prefixlen;
	uint32_t ip;
};

struct conn_arg {
	int fd;
	struct sockaddr_storage peer;
	socklen_t peer_len;
	char peer_str[INET6_ADDRSTRLEN + 16];
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

static struct app_config g_cfg = {
	.listen = { .host = "0.0.0.0", .port = 9000 },
	.upstream = { .host = "127.0.0.1", .port = 19000 },
	.protect_port = 9000,
	.ca_file = "certs/ca.crt",
	.cert_file = "certs/server.crt",
	.key_file = "certs/server.key",
	.handshake_timeout = 10,
	.max_conns = 512,
	.pool_size = 32,
	.local_redirect = 1,
	.verbose = 0,
};

static struct net_cidr g_nets[MAX_NETS];
static int g_net_count;
static char *g_allow_cns[MAX_ALLOW_CN];
static int g_allow_cn_count;

static struct sockaddr_in g_upstream_addr;
static SSL_CTX *g_tls_ctx;
static struct mtls_shield_bpf *g_skel;
static struct bpf_link *g_sk_link;
static struct bpf_link *g_cg_link;
static struct bpf_link *g_bind_link;
static int g_same_port;
static int g_active_conns;
static struct upstream_pool g_pool;

static volatile sig_atomic_t g_stop;
static volatile sig_atomic_t g_want_stats;

static void log_msg(const char *level, const char *fmt, va_list ap)
{
	char ts[32];
	struct tm tm;
	time_t now = time(NULL);

	localtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
	fprintf(stderr, "[%s] %-5s ", ts, level);
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

static int tls_init(void)
{
	STACK_OF(X509_NAME) *ca_names;

	OPENSSL_init_ssl(0, NULL);

	g_tls_ctx = SSL_CTX_new(TLS_server_method());
	if (!g_tls_ctx) {
		log_error("SSL_CTX_new failed: %s", ssl_error_string());
		return -1;
	}

	if (!SSL_CTX_set_min_proto_version(g_tls_ctx, TLS1_2_VERSION)) {
		log_error("failed to set minimum TLS version");
		return -1;
	}
	SSL_CTX_set_options(g_tls_ctx, SSL_OP_NO_COMPRESSION);
	SSL_CTX_set_mode(g_tls_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
				   SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	if (!SSL_CTX_use_certificate_chain_file(g_tls_ctx, g_cfg.cert_file)) {
		log_error("cannot load server certificate %s: %s",
			  g_cfg.cert_file, ssl_error_string());
		return -1;
	}
	if (!SSL_CTX_use_PrivateKey_file(g_tls_ctx, g_cfg.key_file,
					 SSL_FILETYPE_PEM)) {
		log_error("cannot load private key %s: %s", g_cfg.key_file,
			  ssl_error_string());
		return -1;
	}
	if (!SSL_CTX_check_private_key(g_tls_ctx)) {
		log_error("server certificate and key do not match");
		return -1;
	}
	if (!SSL_CTX_load_verify_locations(g_tls_ctx, g_cfg.ca_file, NULL)) {
		log_error("cannot load client CA %s: %s", g_cfg.ca_file,
			  ssl_error_string());
		return -1;
	}

	ca_names = SSL_load_client_CA_file(g_cfg.ca_file);
	if (!ca_names) {
		log_error("cannot build client CA list from %s", g_cfg.ca_file);
		return -1;
	}
	SSL_CTX_set_client_CA_list(g_tls_ctx, ca_names);
	SSL_CTX_set_verify(g_tls_ctx,
			   SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			   verify_client_cert);

	return 0;
}

static int create_listener(void)
{
	struct sockaddr_in addr;
	int fd;
	int one = 1;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		log_error("socket: %s", strerror(errno));
		return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(g_cfg.listen.port);
	if (inet_pton(AF_INET, g_cfg.listen.host, &addr.sin_addr) != 1) {
		log_error("invalid listen address: %s", g_cfg.listen.host);
		close(fd);
		return -1;
	}

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		log_error("bind %s:%d: %s", g_cfg.listen.host,
			  g_cfg.listen.port, strerror(errno));
		if (g_same_port && errno == EADDRINUSE)
			log_error("start mtls_shield before the backend so "
				  "cgroup/bind4 can move the backend's bind() "
				  "to %s:%d",
				  g_cfg.upstream.host, g_cfg.upstream.port);
		close(fd);
		return -1;
	}
	if (listen(fd, 256) < 0) {
		log_error("listen: %s", strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

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

	if (connect(fd, (struct sockaddr *)&g_upstream_addr,
		    sizeof(g_upstream_addr)) < 0) {
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
	struct upstream_pool *pool = opaque;
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

		fd = connect_upstream();
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

static int upstream_pool_get(void)
{
	struct upstream_pool *pool = &g_pool;

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
			return connect_upstream();
		if (upstream_socket_usable(fd))
			return fd;
		close(fd);
	}
}

static void upstream_pool_discard(int fd)
{
	close(fd);
}

static int upstream_pool_start(void)
{
	struct upstream_pool *pool = &g_pool;

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
			   pool) != 0) {
		free(pool->fds);
		pool->fds = NULL;
		pool->capacity = 0;
		return -1;
	}

	pool->running = 1;
	log_info("upstream connection pool: size=%d", pool->capacity);
	return 0;
}

static void upstream_pool_stop(void)
{
	struct upstream_pool *pool = &g_pool;
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

static void print_pool_stats(void)
{
	unsigned long long hits;
	unsigned long long misses;

	if (!g_pool.running)
		return;

	hits = __atomic_load_n(&g_pool.hits, __ATOMIC_RELAXED);
	misses = __atomic_load_n(&g_pool.misses, __ATOMIC_RELAXED);
	log_info("upstream pool: size=%d hits=%llu misses=%llu",
		 g_pool.capacity, hits, misses);
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

	ufd = upstream_pool_get();
	if (ufd < 0) {
		log_error("cannot connect upstream %s:%d for client %s: %s",
			  g_cfg.upstream.host, g_cfg.upstream.port,
			  arg->peer_str, strerror(errno));
		goto out;
	}

	log_info("mTLS ok client=%s cn=%s local=%s upstream=%s:%d",
		 arg->peer_str, cn, local_str, g_cfg.upstream.host,
		 g_cfg.upstream.port);

	relay_loop(ssl, fd, ufd);

out:
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	if (ufd >= 0)
		upstream_pool_discard(ufd);
	close(fd);
	__atomic_sub_fetch(&g_active_conns, 1, __ATOMIC_SEQ_CST);
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

static int bpf_setup(int listen_fd)
{
	struct lpm_key net_key;
	struct shield_cfg cfg;
	uint32_t key = 0;
	uint32_t enabled = 1;
	int netns_fd;
	int map_fd;
	int i;

	g_skel = mtls_shield_bpf__open();
	if (!g_skel) {
		log_error("cannot open BPF skeleton: %s", strerror(errno));
		return -1;
	}

	if (mtls_shield_bpf__load(g_skel)) {
		log_error("cannot load BPF programs: %s", strerror(errno));
		return -1;
	}

	memset(&cfg, 0, sizeof(cfg));
	cfg.enabled = 1;
	cfg.protect_port = htons((uint16_t)g_cfg.protect_port);
	cfg.proxy_port = htons((uint16_t)g_cfg.listen.port);
	if (g_same_port) {
		cfg.backend_ip4 = g_upstream_addr.sin_addr.s_addr;
		cfg.backend_port = htons((uint16_t)g_cfg.upstream.port);
	}

	map_fd = bpf_map__fd(g_skel->maps.shield_cfg_map);
	if (map_fd < 0 ||
	    bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY) != 0) {
		log_error("cannot write shield config map: %s", strerror(errno));
		return -1;
	}

	if (g_same_port) {
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
		return 0;
	}

	map_fd = bpf_map__fd(g_skel->maps.protect_nets);
	for (i = 0; i < g_net_count; i++) {
		net_key.prefixlen = (uint32_t)g_nets[i].prefix;
		net_key.ip = g_nets[i].ip;
		if (bpf_map_update_elem(map_fd, &net_key, &enabled,
					BPF_ANY) != 0) {
			log_error("cannot add protected network: %s",
				  strerror(errno));
			return -1;
		}
	}

	map_fd = bpf_map__fd(g_skel->maps.proxy_socks);
	if (map_fd < 0 ||
	    bpf_map_update_elem(map_fd, &key, &listen_fd, BPF_ANY) != 0) {
		log_error("cannot publish proxy socket to BPF: %s",
			  strerror(errno));
		return -1;
	}

	netns_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (netns_fd < 0) {
		log_error("cannot open current netns: %s", strerror(errno));
		return -1;
	}
	g_sk_link = bpf_program__attach_netns(g_skel->progs.shield_sk_lookup,
					      netns_fd);
	close(netns_fd);
	if (!g_sk_link) {
		log_error("cannot attach sk_lookup program: %s",
			  strerror(errno));
		return -1;
	}
	log_info("attached sk_lookup to current network namespace");

	if (g_cfg.local_redirect) {
		g_cg_link = attach_cgroup_prog(g_skel->progs.shield_connect4,
					       "/sys/fs/cgroup");
		if (g_cg_link)
			log_info("attached cgroup/connect4 to /sys/fs/cgroup");
		else
			log_warn("cgroup/connect4 not attached (%s); "
				 "local clients may bypass redirect",
				 strerror(errno));
	}

	return 0;
}

static int prepare_nets(const char *upstream_ip_str, int upstream_ip_known)
{
	struct ifaddrs *ifas = NULL;
	struct ifaddrs *ifa;
	int i;
	int rc = -1;

	if (g_net_count == 0) {
		if (getifaddrs(&ifas) != 0) {
			log_error("getifaddrs: %s", strerror(errno));
			return -1;
		}
		for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
			uint32_t ip;

			if (!ifa->ifa_addr ||
			    ifa->ifa_addr->sa_family != AF_INET)
				continue;
			ip = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
			if (ip == 0)
				continue;
			if (upstream_ip_known &&
			    g_cfg.upstream.port == g_cfg.protect_port) {
				struct in_addr up;
				if (inet_pton(AF_INET, upstream_ip_str, &up) == 1 &&
				    up.s_addr == ip)
					continue;
			}
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

	if (upstream_ip_known && g_cfg.upstream.port == g_cfg.protect_port) {
		struct in_addr up;

		if (inet_pton(AF_INET, upstream_ip_str, &up) == 1 &&
		    ip_in_nets(up.s_addr)) {
			log_error("upstream %s:%d is inside a protected network; "
				  "the proxy would loop into itself. Use a "
				  "different upstream port or protected CIDR.",
				  upstream_ip_str, g_cfg.upstream.port);
			return -1;
		}
	}

	rc = 0;
	return rc;
}

static void on_signal(int sig)
{
	if (sig == SIGUSR1)
		g_want_stats = 1;
	else
		g_stop = 1;
}

static void install_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);
}

static int wait_for_connections(int timeout_ms)
{
	int waited = 0;

	while (__atomic_load_n(&g_active_conns, __ATOMIC_SEQ_CST) > 0) {
		if (waited >= timeout_ms)
			return -1;
		usleep(10000);
		waited += 10;
	}
	return 0;
}

static void accept_loop(int listen_fd)
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
			print_bpf_stats();
			print_pool_stats();
		}

		pfd.fd = listen_fd;
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
		fd = accept4(listen_fd, (struct sockaddr *)&peer, &peer_len,
			     SOCK_CLOEXEC);
		if (fd < 0) {
			if (errno == EINTR || errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				continue;
			log_error("accept: %s", strerror(errno));
			continue;
		}

		active = __atomic_add_fetch(&g_active_conns, 1,
					    __ATOMIC_SEQ_CST);
		if (active > g_cfg.max_conns) {
			__atomic_sub_fetch(&g_active_conns, 1,
					   __ATOMIC_SEQ_CST);
			log_warn("connection limit reached (%d), rejecting",
				 g_cfg.max_conns);
			close(fd);
			continue;
		}

		arg = calloc(1, sizeof(*arg));
		if (!arg) {
			close(fd);
			__atomic_sub_fetch(&g_active_conns, 1,
					   __ATOMIC_SEQ_CST);
			continue;
		}
		arg->fd = fd;
		arg->peer = peer;
		arg->peer_len = peer_len;
		format_addr(&peer, peer_len, arg->peer_str,
			    sizeof(arg->peer_str));

		if (pthread_create(&thread, NULL, conn_thread, arg) != 0) {
			log_error("pthread_create: %s", strerror(errno));
			close(fd);
			free(arg);
			__atomic_sub_fetch(&g_active_conns, 1,
					   __ATOMIC_SEQ_CST);
			continue;
		}
		pthread_detach(thread);
	}
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [options]\n"
		"\n"
		"  -l, --listen ADDR:PORT        mTLS listener (default 0.0.0.0:9000)\n"
		"  -p, --protect-port PORT       original TCP port (default 9000)\n"
		"  -u, --upstream ADDR:PORT      internal plain service (default 127.0.0.1:19000)\n"
		"  -n, --protect-cidr CIDR       redirect mode: IP/CIDR to intercept\n"
		"  -a, --ca FILE                 client CA bundle (default certs/ca.crt)\n"
		"  -c, --cert FILE               server certificate (default certs/server.crt)\n"
		"  -k, --key FILE                server private key (default certs/server.key)\n"
		"  -C, --allow-cn CN             allowed client cert CN; repeatable\n"
		"  -t, --handshake-timeout SEC   TLS handshake timeout (default 10)\n"
		"  -m, --max-conns N             concurrent connection limit (default 512)\n"
		"  -P, --pool-size N             pre-connected upstream pool (default 32, 0=off)\n"
		"  -L, --no-local-redirect       skip cgroup/connect4 attach\n"
		"  -v, --verbose                 verbose logging\n"
		"  -h, --help                    show this help\n"
		"\n"
		"Default same-port mode: mTLS listens on --protect-port and eBPF\n"
		"rewrites the backend's bind() for that port to --upstream, so the\n"
		"plain service keeps its original configuration. Start mtls_shield\n"
		"before the backend. If --listen differs from --protect-port, the\n"
		"old redirect mode is used (sk_lookup + cgroup/connect4).\n",
		prog);
}

static int parse_args(int argc, char **argv)
{
	static const struct option options[] = {
		{ "listen", required_argument, NULL, 'l' },
		{ "protect-port", required_argument, NULL, 'p' },
		{ "upstream", required_argument, NULL, 'u' },
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

	while ((opt = getopt_long(argc, argv, "l:p:u:n:a:c:k:C:t:m:P:Lvh",
				  options, NULL)) != -1) {
		switch (opt) {
		case 'l':
			if (parse_endpoint(optarg, &g_cfg.listen)) {
				log_error("bad --listen value: %s", optarg);
				return -1;
			}
			break;
		case 'p':
			if (parse_int(optarg, 1, 65535, &g_cfg.protect_port)) {
				log_error("bad --protect-port value: %s", optarg);
				return -1;
			}
			break;
		case 'u':
			if (parse_endpoint(optarg, &g_cfg.upstream)) {
				log_error("bad --upstream value: %s", optarg);
				return -1;
			}
			break;
		case 'n': {
			struct net_cidr net;

			if (parse_cidr(optarg, &net)) {
				log_error("bad --protect-cidr value: %s", optarg);
				return -1;
			}
			if (add_net(net.ip, net.prefix)) {
				log_error("too many protected networks");
				return -1;
			}
			break;
		}
		case 'a':
			g_cfg.ca_file = optarg;
			break;
		case 'c':
			g_cfg.cert_file = optarg;
			break;
		case 'k':
			g_cfg.key_file = optarg;
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
	char upstream_ip[INET_ADDRSTRLEN] = "";
	int upstream_ip_known = 0;
	int listen_fd;
	int rc = EXIT_FAILURE;

	libbpf_set_print(libbpf_print_fn);

	if (parse_args(argc, argv) != 0)
		return EXIT_FAILURE;
	if (geteuid() != 0)
		log_warn("not running as root; BPF load may fail");

	g_same_port = g_cfg.listen.port == g_cfg.protect_port;

	if (resolve_ipv4(g_cfg.upstream.host, &g_upstream_addr.sin_addr) != 0) {
		log_error("cannot resolve upstream host %s", g_cfg.upstream.host);
		return EXIT_FAILURE;
	}
	g_upstream_addr.sin_family = AF_INET;
	g_upstream_addr.sin_port = htons((uint16_t)g_cfg.upstream.port);
	inet_ntop(AF_INET, &g_upstream_addr.sin_addr, upstream_ip,
		  sizeof(upstream_ip));
	upstream_ip_known = 1;

	if (g_same_port && g_cfg.upstream.port == g_cfg.protect_port) {
		log_error("same-port mode needs an internal backend port; "
			  "--upstream must not use tcp/%d",
			  g_cfg.protect_port);
		return EXIT_FAILURE;
	}
	if (g_same_port && !is_local_ipv4(g_upstream_addr.sin_addr.s_addr)) {
		log_error("same-port mode requires --upstream to be a local "
			  "address so the backend bind() can be moved there");
		return EXIT_FAILURE;
	}
	if (g_same_port && g_net_count > 0)
		log_warn("--protect-cidr is ignored in same-port mode");

	if (!g_same_port &&
	    prepare_nets(upstream_ip, upstream_ip_known) != 0)
		return EXIT_FAILURE;

	if (tls_init() != 0)
		return EXIT_FAILURE;

	listen_fd = create_listener();
	if (listen_fd < 0)
		return EXIT_FAILURE;

	if (bpf_setup(listen_fd) != 0)
		goto out_listen;

	if (upstream_pool_start() != 0)
		log_warn("cannot start upstream connection pool; "
			 "falling back to direct connects");

	install_signals();

	if (g_same_port)
		log_info("ready: mTLS on original tcp/%d (%s:%d); eBPF will "
			 "move the backend's bind() to %s:%d",
			 g_cfg.protect_port, g_cfg.listen.host,
			 g_cfg.listen.port, upstream_ip, g_cfg.upstream.port);
	else
		log_info("ready: tcp/%d redirected via eBPF to mTLS %s:%d, "
			 "upstream %s:%d",
			 g_cfg.protect_port, g_cfg.listen.host,
			 g_cfg.listen.port, upstream_ip, g_cfg.upstream.port);

	accept_loop(listen_fd);
	print_bpf_stats();
	print_pool_stats();
	rc = EXIT_SUCCESS;

	if (wait_for_connections((g_cfg.handshake_timeout + 10) * 1000) == 0)
		upstream_pool_stop();
	else
		log_warn("connections still active at shutdown; "
			 "skipping upstream pool cleanup");

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

out_listen:
	if (g_skel) {
		mtls_shield_bpf__destroy(g_skel);
		g_skel = NULL;
	}
	if (g_tls_ctx) {
		SSL_CTX_free(g_tls_ctx);
		g_tls_ctx = NULL;
	}
	close(listen_fd);
	return rc;
}
