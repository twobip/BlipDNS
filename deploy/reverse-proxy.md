# blipc behind a reverse proxy (TLS termination)

`blipc` itself serves plain HTTP. For remote admin access, bind it to
loopback and terminate TLS in a reverse proxy on the same host or mgmt VLAN.

## 1. blipc config (`/etc/blipc/blipc.yaml`)

```yaml
listen: "127.0.0.1:8500"
# Trust the local proxy for X-Forwarded-* (client IP, proto, host).
trusted_proxies: ["127.0.0.1/32", "::1/128"]
# Use password_hash (bcrypt), never plaintext password in production.
# password_hash: "$2b$10$..."
```

With `trusted_proxies` set, blipc:

- uses the LAST `X-Forwarded-For` / `CF-Connecting-IP` token for login
  rate-limit buckets, probe limits and audit logs (untrusted peers: direct
  `RemoteAddr` only). The last token is the address the trusted proxy
  appended, so a client-supplied first token (e.g. preserved by nginx
  `$proxy_add_x_forwarded_for`) is never honored. Configure the proxy to
  append (default `$proxy_add_x_forwarded_for`) or overwrite — either is
  safe, because only the proxy-added rightmost value is trusted. Never list
  an untrusted network in `trusted_proxies`.
- `CF-Connecting-IP` is honored only from a configured trusted peer: only
  list Cloudflare Tunnel / proxy addresses there, never `0.0.0.0/0`.
- sets `Secure` on the session cookie when `X-Forwarded-Proto: https`
  arrives from a trusted peer (plus `HttpOnly` + `SameSite=Strict` always),
- sends `Strict-Transport-Security` when the client-facing proto is https,
- validates CSRF `Origin`/`Referer` against `X-Forwarded-Host` (trusted peers)
  instead of the internal `127.0.0.1:8500`.

Without `trusted_proxies`, forwarded headers are ignored: cookies never get
`Secure` via the proxy and CSRF checks compare against the internal host
(which breaks proxied browsers — set `trusted_proxies`).

## 2. nginx example

```nginx
upstream blipc { server 127.0.0.1:8500; }

server {
  listen 443 ssl;
  server_name dns-admin.example.com;

  ssl_certificate /etc/ssl/dns-admin.crt;
  ssl_certificate_key /etc/ssl/dns-admin.key;

  location / {
    proxy_pass http://blipc;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    proxy_read_timeout 90s; # SSE /api/events keepalive is 15s
  }
}
```

## 3. caddy example

```
dns-admin.example.com {
  reverse_proxy 127.0.0.1:8500
}
```

Caddy sets `X-Forwarded-For/Proto/Host` automatically; keep blipc's
`trusted_proxies: ["127.0.0.1/32", "::1/128"]`.

## 5. Proxy on a different host (backend over LAN)

Plain `http://blipc:8500` across the LAN leaks session cookies + fleet tokens
to passive sniffing. Serve the backend over HTTPS with the same self-signed
mechanism as DoH:

```yaml
# /etc/blipc/blipc.yaml (on the blipc host)
listen: "0.0.0.0:8500"  # or the LAN IP; firewall to proxy IP only
trusted_proxies: ["<proxy-lan-ip>/32"]
dashboard_tls: true
tls_dir: "/var/lib/blipc"
tls_san: ["dns-admin.example.com", "192.168.30.10"]
```

```nginx
# on the proxy host: re-encrypt to the backend (self-signed, pin by default
# off for internal hosts; or add proxy_ssl_trusted_certificate + verify on)
location / {
  proxy_pass https://blipc-lan:8500;
  proxy_ssl_verify off;  # backend is self-signed TOFU; WG/VLAN is the real auth
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Forwarded-Host $host;
}
```

To reuse the exact blipd DoH pair when co-located instead of a separate
dashboard cert:

```yaml
tls_cert_file: "/etc/blipd/tls.crt"  # or /var/lib/blipd/doh-cert.pem
tls_key_file: "/etc/blipd/tls.key"
```

Note: `blipc` (user `blipc`) must be able to read those paths — separate
dashboard certs under `/var/lib/blipc` avoid cross-user key access.

## 4. Checks

- `curl -Ik https://dns-admin.example.com/login` → `Secure` on
  `Set-Cookie: blip_session` after POST `/api/login`.
- `curl -Ik` shows `strict-transport-security: max-age=31536000`.
- Logs show real client IPs, not `127.0.0.1`.
- Do NOT expose `blipd` `:8444` via the proxy: keep it on `127.0.0.1`
  (bearer tokens, no TLS). Only `blipc :8500` is proxy-safe.
