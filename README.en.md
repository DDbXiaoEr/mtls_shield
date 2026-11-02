# mtls_shield

Add mTLS directly on the **original port** of an ordinary TCP service using eBPF — no changes to the service code or its startup arguments.

```
client ──TLS:9000──▶ mtls_shield (listens on the original port, terminates OpenSSL mTLS)
                              │
                              └──plain TCP:19000──▶ original plaintext service
```

The key point: port 9000 is bound directly by `mtls_shield`; there is no extra TLS proxy port.
The backend's `bind(9000)` is transparently rewritten at the syscall level by the eBPF
`cgroup/bind4` program to `127.0.0.1:19000`, so the backend still believes it is listening
on 9000 and neither its code nor its configuration needs to change.

## Design

The TLS handshake and certificate verification must happen in user space; eBPF is not suitable
for cryptography in the kernel. The responsibilities are split as follows:

1. **eBPF `cgroup/bind4`**: when the backend process calls `bind(..., 9000)`, rewrite the port
   to the internal port `19000` and restrict the listen address to loopback. The backend process
   is completely unaware.
2. **`mtls_shield` listens on the original port 9000**: it accepts client TLS connections
   directly and enforces client certificate verification.
3. **Plaintext forwarding**: decrypted TLS data is sent to the original service over
   `127.0.0.1:19000`.

Clients only ever see 9000; there is no second proxy port.

### Why the backend must have an internal port

Two processes cannot listen on the same IP/port at the same time. To terminate TLS on 9000,
`mtls_shield` must own 9000, and the original plaintext service has to move elsewhere. The
value of the eBPF `bind4` program is:

- no service code changes;
- no changes to the service's listen-port configuration;
- the internal port is bound to loopback only and is not exposed externally.

If the service can be changed to use a Unix socket, the internal channel can be a Unix socket
instead, but that requires modifying the service.

### Optional redirect mode

If the port given by `--listen` differs from `--protect-port`, the program automatically uses
the legacy redirect mode: `mtls_shield` listens on another port, and eBPF `sk_lookup` +
`cgroup/connect4` transparently redirect connections from the original port to it. The default
configuration does not use this mode.

## Layout

```
.
├── Makefile
├── README.md
├── README.en.md
├── LICENSE
├── src
│   ├── mtls_shield.bpf.c   eBPF: cgroup/bind4 (same-port mode) + sk_lookup/connect4 (redirect mode)
│   └── mtls_shield.c       user space: load eBPF, TLS listener, mTLS verification, bidirectional forwarding
└── scripts
    ├── gen_certs.sh        generate CA / server cert / client cert / rogue test certs
    ├── demo_backend.py     ordinary plaintext HTTP backend
    └── demo.sh             one-shot build + start + end-to-end test
```

## Requirements

- Linux kernel >= 5.9 with `CONFIG_BPF_SYSCALL`, `CONFIG_INET`,
  `CONFIG_CGROUP_BPF` enabled
- cgroup v2
- root privileges (`CAP_BPF` + `CAP_NET_ADMIN`)
- `clang`, `bpftool`, `libbpf-dev`, `libssl-dev`, `pkg-config`, `curl`
- `/sys/kernel/btf/vmlinux` available on the target kernel (present by default on Ubuntu/Debian)

### Why >= 5.9 is required

- The `sk_lookup` program type and the `bpf_sk_assign()` helper were both introduced in
  **Linux 5.9** (see `src/mtls_shield.bpf.c`).
- The skeleton **loads all BPF programs unconditionally**, so even in same-port mode (which
  does not use redirect) a kernel below 5.9 fails directly at the load stage.
- Same-port mode itself only depends on `cgroup/bind4` (4.17+), so 4.18/5.x could work in
  theory: use `bpf_program__set_autoload()` to skip `sk_lookup`/`connect4` per mode, or split
  the two modes into separate objects.
- Going below 5.2 is not recommended in practice: the project relies on kernel BTF
  (`/sys/kernel/btf/vmlinux`) to generate `vmlinux.h`, and CO-RE needs it too. 5.10 LTS is
  recommended for production.

Install dependencies on Ubuntu:

```bash
sudo apt-get install -y clang llvm bpftool libbpf-dev libssl-dev \
    pkg-config make gcc iproute2 curl
```

## Build

```bash
make
```

The build uses the target machine's BTF to generate `src/vmlinux.h`, so build on the machine
where you will run it. The output is `./mtls_shield`.

## Generate certificates

```bash
HOST_IP=172.16.74.195 ./scripts/gen_certs.sh certs
```

`HOST_IP` is written into the server certificate's SAN. The certificates are:

- `ca.crt` / `ca.key`: the trusted CA
- `server.crt` / `server.key`: the server certificate
- `client.crt` / `client.key`: a valid client certificate (CN=alice)
- `rogue-ca.*` / `rogue-client.*`: an untrusted client certificate for negative tests

## Run

**Order matters: start `mtls_shield` first, then start the original service.** The eBPF program
must be attached before the service calls `bind(9000)` in order to rewrite its listen port.

1. Start the mTLS layer, taking over the original port 9000:

```bash
sudo ./mtls_shield \
  --listen 0.0.0.0:9000 \
  --protect-port 9000 \
  --upstream 127.0.0.1:19000 \
  --ca certs/ca.crt \
  --cert certs/server.crt \
  --key certs/server.key
```

By default **CN is not restricted**: any CN is accepted as long as the client certificate
chains to the CA specified by `--ca` and is within its validity period. The CN allowlist is
enabled only when `--allow-cn` is passed explicitly. Adding `--allow-cn alice` to the command
above would allow only CN=alice.

2. Then start the original service. It still listens on 9000 according to its original config:

```bash
python3 scripts/demo_backend.py --host 127.0.0.1 --port 9000
```

eBPF rewrites its actual listen address to `127.0.0.1:19000`. You can verify:

```bash
ss -ltnp | grep -E ':(9000|19000)'
# mtls_shield listens on 0.0.0.0:9000
# python3     listens on 127.0.0.1:19000
```

3. Clients still connect to 9000, but it is now mTLS:

```bash
curl --cacert certs/ca.crt \
     --cert certs/client.crt \
     --key certs/client.key \
     https://172.16.74.195:9000/
```

Without a client certificate:

```bash
curl --cacert certs/ca.crt https://172.16.74.195:9000/
# handshake fails
```

Plaintext access to the original port:

```bash
curl http://172.16.74.195:9000/
# handshake fails
```

The internal backend remains plaintext:

```bash
curl http://127.0.0.1:19000/
# 200, proving the original service is unchanged
```

### One-shot demo

The script builds, generates certificates, **starts the shield before the backend**, and verifies:

- eBPF rewrites the backend's bind from 9000 to 19000
- mTLS succeeds on the original port
- requests without a client certificate, with an untrusted CA, or over plaintext HTTP are rejected
- forwarding of a 1 MiB response and a 256 KiB request
- access to the original port from a separate netns simulating a remote client

```bash
sudo ./scripts/demo.sh
```

## Options

| Option | Default | Description |
| --- | --- | --- |
| `-l, --listen ADDR:PORT` | `0.0.0.0:9000` | mTLS listen address; identical to `--protect-port` means same-port mode |
| `-p, --protect-port PORT` | `9000` | original TCP port |
| `-u, --upstream ADDR:PORT` | `127.0.0.1:19000` | internal plaintext service address, also the bind rewrite target |
| `-n, --protect-cidr CIDR` | all local IPv4 addresses | used only in redirect mode |
| `-a, --ca FILE` | `certs/ca.crt` | client certificate CA |
| `-c, --cert FILE` | `certs/server.crt` | server certificate chain |
| `-k, --key FILE` | `certs/server.key` | server private key |
| `-C, --allow-cn CN` | unrestricted | allowed client certificate CN, repeatable |
| `-t, --handshake-timeout SEC` | `10` | TLS handshake timeout |
| `-m, --max-conns N` | `512` | maximum concurrent connections |
| `-L, --no-local-redirect` | off | do not attach `cgroup/connect4` in redirect mode |
| `-v, --verbose` | off | print libbpf debug logs |
| `-h, --help` | | help |

After startup, send `SIGUSR1` to the process to print BPF statistics:

```bash
sudo kill -USR1 <pid>
```

Statistics:

- `bind_redirect`: number of backend `bind()` calls rewritten in same-port mode
- `sk_lookup_redirect` / `connect_redirect`: redirect counts in redirect mode
- `no_proxy_socket` / `assign_error`: error counters in redirect mode
- `sk_lookup_seen` / `port_match`: debug counters

## Security notes

- TLS 1.2 and above only.
- A client certificate is mandatory (`SSL_VERIFY_FAIL_IF_NO_PEER_CERT`).
- The client certificate must chain to the CA specified by `--ca`.
- Optional `--allow-cn` provides a second layer of identity allowlisting.
- Plaintext clients fail the handshake and cannot bypass mTLS.
- eBPF forces the backend listen address to loopback, so the plaintext backend cannot be reached externally.
- The proxy logs client addresses and certificate CNs, but never private keys or plaintext application data.

## Limitations

- IPv4 only for now; IPv6 needs `cgroup/bind6` plus IPv6 maps/programs.
- The shield must start before the service. Attaching eBPF after the service has started cannot retroactively rewrite a completed `bind()`.
- The backend's `getsockname()` sees the real internal port 19000; services that advertise their listen port in responses or self-connect need attention.
- `cgroup/bind4` is attached to `/sys/fs/cgroup` and rewrites every subsequent `bind()` on the original port. In production, put the backend in its own cgroup and attach the program to that cgroup.
- mTLS terminates at the proxy; the proxy-to-backend hop is plaintext over loopback.
- No SNI routing, TLS passthrough, or CRL/OCSP.
- One thread per connection, suitable for demos and moderate traffic; high-concurrency workloads should use an event-driven model or a connection pool.
- Redirect mode is still supported but not used by default.

## Troubleshooting

```bash
# Confirm bind4 / sk_lookup are loaded
sudo bpftool link list
sudo bpftool prog show name shield_bind4

# Inspect listeners: 9000 should be mtls_shield, 19000 should be the original service
ss -ltnp | grep -E ':(9000|19000)'

# Follow the proxy log
tail -f demo.log
```

Common issues:

- **`bind 0.0.0.0:9000: Address already in use` on startup**: the backend started first.
  Stop the backend, start `mtls_shield`, then start the backend again. The program log also
  prints this hint.
- **The backend is still on 9000**: check that `ss` shows the backend on 19000; if not, `bind4`
  was not attached, or the backend started before the shield.
- **curl reports a certificate hostname mismatch**: `HOST_IP` did not include the IP used to
  connect when generating the certificates.
- **Remote access fails**: make sure `--listen 0.0.0.0:9000` and that the firewall allows 9000.
- **`--allow-cn` has no effect**: make sure the certificate's Subject CN is exactly the configured value.
- **Leftover ports/resources**: the process detaches the eBPF links on exit; `bpftool link list`
  should no longer contain the corresponding `bind4`/`sk_lookup` entries.

## License

Released under the [WTFPL](LICENSE) (Do What The Fuck You Want To Public License).
