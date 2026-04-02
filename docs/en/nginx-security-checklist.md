---
title: "NGINX Security Checklist 2026"
description: "Printable NGINX security hardening checklist. 40+ actionable items covering SSL/TLS, headers, access control, and configuration best practices."
keywords: "nginx security checklist, nginx hardening checklist, nginx security audit, nginx security best practices, nginx configuration checklist"
---

# NGINX Security Checklist

A comprehensive, actionable checklist for securing your NGINX server. Use this for security audits, compliance reviews, or hardening new deployments.

!!! tip "Automate This Checklist"
    Instead of manually checking each item, run `gixy /etc/nginx/nginx.conf` to automatically detect many of these issues. [Learn more →](index.md)

---

## Version & Information Disclosure

- [ ] **Hide NGINX version** — Set `server_tokens off;` in http block
- [ ] **Custom error pages** — Replace default error pages that may leak version info
- [ ] **Remove Server header** — Use `more_clear_headers Server;` (requires headers-more module)
- [ ] **Hide PHP version** — Set `expose_php = Off` in php.ini

??? example "Configuration"
    ```nginx
    http {
        server_tokens off;

        # Custom error pages
        error_page 404 /custom_404.html;
        error_page 500 502 503 504 /custom_50x.html;
    }
    ```

:white_check_mark: **Gixy Check:** [`version_disclosure`](checks/version-disclosure.md)

---

## SSL/TLS Configuration

- [ ] **Disable legacy protocols** — Only allow TLSv1.2 and TLSv1.3
- [ ] **Use strong ciphers** — Follow Mozilla Intermediate or Modern configuration
- [ ] **Disable weak ciphers** — No RC4, DES, 3DES, EXPORT, NULL ciphers
- [ ] **Enable OCSP stapling** — Reduces latency and improves privacy
- [ ] **Configure session resumption** — Use `ssl_session_cache` and `ssl_session_tickets`
- [ ] **Use 2048+ bit DH parameters** — Generate with `openssl dhparam -out dhparam.pem 4096`
- [ ] **Valid certificates** — Check expiration, chain completeness

??? example "Configuration"
    ```nginx
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ```

:white_check_mark: **Gixy Check:** [`weak_ssl_tls`](checks/weak-ssl-tls.md)

---

## Security Headers

- [ ] **HSTS enabled** — `Strict-Transport-Security` with appropriate max-age
- [ ] **X-Frame-Options** — Set to `DENY` or `SAMEORIGIN`
- [ ] **X-Content-Type-Options** — Set to `nosniff`
- [ ] **X-XSS-Protection** — Set to `1; mode=block`
- [ ] **Referrer-Policy** — Set appropriate policy for your use case
- [ ] **Content-Security-Policy** — Define allowed content sources
- [ ] **Permissions-Policy** — Restrict browser feature access
- [ ] **Headers in all contexts** — Verify headers aren't lost in location blocks

??? example "Configuration"
    ```nginx
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self';" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    ```

:white_check_mark: **Gixy Checks:** [`hsts_header`](checks/hsts-header.md), [`add_header_redefinition`](checks/add-header-redefinition.md)

---

## Host & Server Configuration

- [ ] **Default server defined** — Reject requests to unknown Host headers
- [ ] **Default server returns 444** — Close connection without response
- [ ] **Each vhost has explicit server_name** — No catch-all configurations
- [ ] **HTTP to HTTPS redirect** — Redirect all HTTP traffic to HTTPS
- [ ] **No wildcard server_name in production** — Use explicit hostnames

??? example "Configuration"
    ```nginx
    # Default catch-all server
    server {
        listen 80 default_server;
        listen 443 ssl default_server;
        server_name _;
        ssl_certificate /etc/nginx/ssl/dummy.crt;
        ssl_certificate_key /etc/nginx/ssl/dummy.key;
        return 444;
    }

    # HTTP to HTTPS redirect
    server {
        listen 80;
        server_name example.com;
        return 301 https://$server_name$request_uri;
    }
    ```

:white_check_mark: **Gixy Checks:** [`host_spoofing`](checks/host-spoofing.md), [`default_server_flag`](checks/default-server-flag.md)

---

## Access Control

- [ ] **Complete allow/deny rules** — Every `allow` block ends with `deny all;`
- [ ] **Protect sensitive files** — Block access to `.git`, `.env`, `.htaccess`, etc.
- [ ] **Protect backup files** — Block `.bak`, `.old`, `.swp`, `.tmp` files
- [ ] **Admin area restricted** — Limit access by IP or authentication
- [ ] **Upload directory restrictions** — Disable PHP/script execution in upload paths
- [ ] **Return doesn't bypass access control** — Be aware of directive processing order

??? example "Configuration"
    ```nginx
    # Block sensitive files
    location ~ /\. {
        deny all;
    }

    location ~* \.(git|svn|env|htaccess|htpasswd)$ {
        deny all;
    }

    # Admin area
    location /admin {
        allow 10.0.0.0/8;
        deny all;
        auth_basic "Admin Area";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }

    # Uploads - no script execution
    location /uploads {
        location ~ \.(php|py|pl|cgi)$ {
            deny all;
        }
    }
    ```

:white_check_mark: **Gixy Checks:** [`allow_without_deny`](checks/allow-without-deny.md), [`return_bypasses_allow_deny`](checks/return-bypasses-allow-deny.md)

---

## Path & File Handling

- [ ] **Alias trailing slash** — Location with `alias` must end with `/`
- [ ] **No user-controlled paths** — Don't interpolate user input in file paths
- [ ] **Verify root vs alias** — Understand the difference
- [ ] **Limit try_files scope** — Be careful with `try_files` and user input

??? example "Configuration"
    ```nginx
    # CORRECT: trailing slash on both
    location /static/ {
        alias /var/www/static/;
    }

    # ALTERNATIVE: use root instead
    location /static/ {
        root /var/www;
    }
    ```

:white_check_mark: **Gixy Checks:** [`alias_traversal`](checks/alias-traversal.md), [`try_files_is_evil_too`](checks/try-files-is-evil-too.md)

---

## Proxy Configuration

- [ ] **No user-controlled proxy_pass** — Hardcode upstream servers
- [ ] **Internal locations protected** — Use `internal;` directive
- [ ] **Proper header forwarding** — Set Host, X-Real-IP, X-Forwarded-For
- [ ] **Timeout limits** — Configure connect, send, read timeouts
- [ ] **Resolver configured for variables** — Required when using variables in proxy_pass

??? example "Configuration"
    ```nginx
    upstream backend {
        server 127.0.0.1:8080;
        keepalive 32;
    }

    location /api/ {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    ```

:white_check_mark: **Gixy Checks:** [`ssrf`](checks/ssrf.md), [`missing_resolver`](checks/missing-resolver.md), [`proxy_pass_normalized`](checks/proxy-pass-normalized.md)

---

## Rate Limiting & DoS Protection

- [ ] **Connection limits** — Use `limit_conn_zone` and `limit_conn`
- [ ] **Request rate limits** — Use `limit_req_zone` and `limit_req`
- [ ] **Stricter limits for auth endpoints** — Lower rates for login, registration
- [ ] **Request body size limit** — Set appropriate `client_max_body_size`
- [ ] **Header buffer limits** — Configure `large_client_header_buffers`
- [ ] **Timeout values** — Set reasonable client_body_timeout, client_header_timeout

??? example "Configuration"
    ```nginx
    http {
        limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
        limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
        limit_conn_zone $binary_remote_addr zone=addr:10m;

        client_max_body_size 10m;
        client_body_timeout 12s;
        client_header_timeout 12s;
        large_client_header_buffers 4 16k;

        server {
            limit_req zone=general burst=20 nodelay;
            limit_conn addr 10;

            location /login {
                limit_req zone=login burst=5 nodelay;
            }
        }
    }
    ```

---

## Logging & Monitoring

- [ ] **Error logging enabled** — Never use `error_log off;`
- [ ] **Access logging enabled** — Log all requests with useful information
- [ ] **Security-focused log format** — Include client IP, user agent, response time
- [ ] **Log rotation configured** — Use logrotate to manage log files
- [ ] **Log monitoring in place** — Forward to SIEM or monitoring system

??? example "Configuration"
    ```nginx
    log_format security '$remote_addr - $remote_user [$time_local] '
                        '"$request" $status $body_bytes_sent '
                        '"$http_referer" "$http_user_agent" '
                        '$request_time $upstream_response_time';

    access_log /var/log/nginx/access.log security;
    error_log /var/log/nginx/error.log warn;
    ```

:white_check_mark: **Gixy Check:** [`error_log_off`](checks/error-log-off.md)

---

## Configuration Hygiene

- [ ] **No `if` in location blocks** — Use `map` or `try_files` instead when possible
- [ ] **Valid regex patterns** — Test all regex with `nginx -t`
- [ ] **Anchored regex** — Use `^` and `$` to prevent partial matches
- [ ] **No ReDoS vulnerabilities** — Avoid catastrophic backtracking
- [ ] **Proper map defaults** — Always define default values in map blocks
- [ ] **Comments in config** — Document non-obvious configurations

:white_check_mark: **Gixy Checks:** [`if_is_evil`](checks/if-is-evil.md), [`invalid_regex`](checks/invalid-regex.md), [`unanchored_regex`](checks/unanchored-regex.md), [`regex_redos`](checks/regex-redos.md), [`hash_without_default`](checks/hash-without-default.md)

---

## Performance & Resource Limits

- [ ] **Worker processes** — Set to `auto` or number of CPU cores
- [ ] **Worker connections** — Set based on expected load (1024-4096 typical)
- [ ] **File descriptor limits** — Ensure `worker_rlimit_nofile` matches system limits
- [ ] **Keepalive tuning** — Set appropriate `keepalive_timeout` and `keepalive_requests`
- [ ] **Gzip enabled** — Compress text-based responses
- [ ] **Buffer tuning** — Optimize proxy and fastcgi buffers

:white_check_mark: **Gixy Checks:** [`worker_rlimit_nofile_vs_connections`](checks/worker-rlimit-nofile-vs-connections.md), [`low_keepalive_requests`](checks/low-keepalive-requests.md)

---

## File System Security

- [ ] **Config file permissions** — `chmod 640 /etc/nginx/nginx.conf`
- [ ] **Private key permissions** — `chmod 600` for SSL private keys
- [ ] **Ownership** — Config owned by root, logs by www-data
- [ ] **SELinux/AppArmor** — Configure MAC policies if enabled
- [ ] **No world-writable directories** — Check document root permissions

```bash
# Check and fix permissions
chmod 640 /etc/nginx/nginx.conf
chmod 750 /etc/nginx/conf.d
chmod 600 /etc/nginx/ssl/*.key
chown -R root:root /etc/nginx
chown -R www-data:www-data /var/log/nginx
```

---

## Validation & Testing

- [ ] **Config syntax test** — Run `nginx -t` after every change
- [ ] **Security scan with Gixy** — Run `gixy /etc/nginx/nginx.conf`
- [ ] **SSL Labs test** — Score A or A+ at [ssllabs.com/ssltest](https://www.ssllabs.com/ssltest/)
- [ ] **Security headers test** — Check at [securityheaders.com](https://securityheaders.com/)
- [ ] **Mozilla Observatory** — Check at [observatory.mozilla.org](https://observatory.mozilla.org/)

---

## Quick Validation Commands

```bash
# Test configuration syntax
nginx -t

# Security scan with Gixy
gixy /etc/nginx/nginx.conf

# Check full config dump
nginx -T

# Test specific config file
nginx -t -c /path/to/nginx.conf

# Reload after changes
nginx -s reload
```

---

## Download This Checklist

Print this page or save it as PDF for offline use. For automated checking, use Gixy:

```bash
pip install gixy-ng
gixy /etc/nginx/nginx.conf --format json > audit-results.json
```

See the [CI/CD Integration Guide](ci-cd-integration.md) for automated security checks in your pipeline.

---

## Related Resources

- [Complete NGINX Hardening Guide](nginx-hardening-guide.md) — Detailed explanations and configurations
- [Security Headers Guide](nginx-security-headers.md) — Deep dive into HTTP security headers
- [Gixy Documentation](index.md) — Full list of automated security checks
- [Online NGINX Checker](https://www.getpagespeed.com/check-nginx-config) — Paste your config for instant analysis

--8<-- "en/snippets/nginx-extras-cta.md"
