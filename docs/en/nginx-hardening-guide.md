---
title: "Complete NGINX Hardening Guide 2026"
description: "Step-by-step NGINX security hardening guide. Cover SSL/TLS, headers, access control, rate limiting, and more. Automate checks with Gixy."
keywords: "nginx hardening, nginx security, nginx hardening guide, nginx security best practices, nginx hardening checklist, secure nginx configuration"
---

# Complete NGINX Hardening Guide

This comprehensive guide covers everything you need to harden your NGINX server against common attacks and misconfigurations. Each section includes the vulnerability, the fix, and how Gixy can automatically detect the issue.

!!! tip "Automate Security Checks"
    Don't manually audit your nginx.conf—run `gixy /etc/nginx/nginx.conf` to catch these issues automatically. [Get started →](index.md)

---

## 1. Hide NGINX Version Information

**Risk Level:** Medium
**Attack Vector:** Information disclosure helps attackers target known CVEs

By default, NGINX exposes its version number in HTTP response headers and error pages. This helps attackers identify which vulnerabilities apply to your server.

### Vulnerable Configuration

```nginx
http {
    # server_tokens defaults to 'on' if not specified
    server {
        listen 80;
        server_name example.com;
    }
}
```

Response header: `Server: nginx/1.24.0`

### Hardened Configuration

```nginx
http {
    server_tokens off;  # Hide version in headers and error pages

    server {
        listen 80;
        server_name example.com;
    }
}
```

Response header: `Server: nginx`

!!! success "Gixy Detection"
    Gixy's [`version_disclosure`](checks/version-disclosure.md) check automatically detects both explicit `server_tokens on;` and missing directives that default to version disclosure.

---

## 2. Configure Secure SSL/TLS

**Risk Level:** Critical
**Attack Vector:** POODLE, BEAST, Sweet32, downgrade attacks

Weak SSL/TLS configuration can allow attackers to decrypt traffic or perform man-in-the-middle attacks.

### Vulnerable Configuration

```nginx
server {
    listen 443 ssl;
    ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;  # Legacy protocols
    ssl_ciphers ALL;  # Includes weak ciphers
}
```

### Hardened Configuration (Mozilla Intermediate)

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name example.com;

    # Modern protocols only
    ssl_protocols TLSv1.2 TLSv1.3;

    # Strong cipher suites (Mozilla Intermediate)
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;

    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;

    # curl https://ssl-config.mozilla.org/ffdhe2048.txt > /etc/nginx/ffdhe2048.txt
    # or
    # openssl dhparam -out /etc/nginx/ffdhe2048.txt 2048
    ssl_dhparam /etc/nginx/ffdhe2048.txt

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
}
```

!!! success "Gixy Detection"
    Gixy's [`weak_ssl_tls`](checks/weak-ssl-tls.md) check detects insecure protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1) and weak cipher suites (RC4, DES, 3DES, EXPORT, NULL).

---

## 3. Enable HTTP Strict Transport Security (HSTS)

**Risk Level:** High
**Attack Vector:** SSL stripping, downgrade attacks

HSTS tells browsers to always use HTTPS, preventing SSL stripping attacks.

### Vulnerable Configuration

```nginx
server {
    listen 443 ssl;
    # Missing HSTS header - vulnerable to SSL stripping
}
```

### Hardened Configuration

```nginx
server {
    listen 443 ssl;
    http2 on;

    # HSTS with 1 year max-age and subdomain inclusion
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}
```

!!! warning "HSTS Considerations"
    - Start with a short `max-age` (e.g., 300) during testing
    - Only add `preload` if you're ready to submit to the [HSTS preload list](https://hstspreload.org/)
    - Ensure ALL subdomains support HTTPS before using `includeSubDomains`

!!! success "Gixy Detection"
    Gixy's [`hsts_header`](checks/hsts-header.md) check detects missing or misconfigured HSTS headers on HTTPS servers.

---

## 4. Add Security Headers

**Risk Level:** Medium-High
**Attack Vector:** XSS, clickjacking, MIME sniffing attacks

Security headers provide defense-in-depth against various client-side attacks.

### Hardened Configuration

```nginx
server {
    listen 443 ssl;
    http2 on;

    # Prevent clickjacking
    add_header X-Frame-Options "SAMEORIGIN" always;

    # Prevent MIME type sniffing
    add_header X-Content-Type-Options "nosniff" always;

    # XSS Protection (legacy browsers)
    add_header X-XSS-Protection "1; mode=block" always;

    # Referrer policy
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Content Security Policy (customize for your app)
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;

    # Permissions Policy
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
}
```

!!! danger "Header Inheritance Warning"
    NGINX's `add_header` directives in child blocks **completely override** parent block headers. If you add any header in a location block, you must re-add ALL security headers.

!!! success "Gixy Detection"
    Gixy's [`add_header_redefinition`](checks/add-header-redefinition.md) check detects when child blocks accidentally clear security headers defined in parent blocks.

---

## 5. Prevent Host Header Spoofing

**Risk Level:** High
**Attack Vector:** Cache poisoning, password reset poisoning, SSRF

Without a default server that rejects unknown hosts, attackers can send requests with arbitrary Host headers.

### Vulnerable Configuration

```nginx
server {
    listen 80;
    server_name example.com;
    # First server block becomes default - accepts any Host header
}
```

### Hardened Configuration

```nginx
# Default server that rejects unknown hosts
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    server_name _;

    ssl_certificate /path/to/dummy.crt;
    ssl_certificate_key /path/to/dummy.key;

    return 444;  # Close connection without response
}

# Your actual server
server {
    listen 80;
    listen 443 ssl;
    server_name example.com www.example.com;
    # ... your config
}
```

!!! success "Gixy Detection"
    Gixy's [`host_spoofing`](checks/host-spoofing.md) and [`default_server_flag`](checks/default-server-flag.md) checks detect missing default server configurations and potential host header attacks.

---

## 6. Implement Access Control

**Risk Level:** High
**Attack Vector:** Unauthorized access, information disclosure

Restrict access to sensitive locations and always use complete allow/deny rules.

### Vulnerable Configuration

```nginx
location /admin {
    allow 192.168.1.0/24;
    # Missing 'deny all' - other IPs can still access!
}
```

### Hardened Configuration

```nginx
# Restrict admin area
location /admin {
    allow 10.0.0.0/8;
    allow 192.168.1.0/24;
    deny all;  # Always end with deny all
}

# Block access to sensitive files
location ~ /\. {
    deny all;
}

location ~* \.(git|svn|env|htaccess|htpasswd)$ {
    deny all;
}

# Block access to backup files
location ~* \.(bak|backup|old|orig|save|swp|tmp)$ {
    deny all;
}
```

!!! success "Gixy Detection"
    Gixy's [`allow_without_deny`](checks/allow-without-deny.md) check detects incomplete access control rules that don't end with `deny all`.

---

## 7. Prevent Path Traversal with Alias

**Risk Level:** Critical
**Attack Vector:** Directory traversal, arbitrary file read

The `alias` directive is prone to path traversal vulnerabilities when the location doesn't end with `/`.

### Vulnerable Configuration

```nginx
location /static {
    alias /var/www/static/;  # VULNERABLE: missing trailing slash in location
}
```

Attack: `GET /static../etc/passwd` → reads `/var/www/static/../etc/passwd` → `/var/www/etc/passwd`

### Hardened Configuration

```nginx
# Option 1: Add trailing slash to location
location /static/ {
    alias /var/www/static/;
}

# Option 2: Use root instead of alias
location /static/ {
    root /var/www;
}
```

!!! success "Gixy Detection"
    Gixy's [`alias_traversal`](checks/alias-traversal.md) check detects alias configurations vulnerable to path traversal attacks.

---

## 8. Secure Proxy Configurations

**Risk Level:** Critical
**Attack Vector:** SSRF, HTTP request smuggling

Improperly configured reverse proxies can allow Server-Side Request Forgery (SSRF) attacks.

### Vulnerable Configuration

```nginx
# SSRF vulnerability - attacker controls proxy destination
location ~ /proxy/(.*)/(.*)/(.*)$ {
    proxy_pass $1://$2/$3;
}
```

### Hardened Configuration

```nginx
# Hardcoded upstream - no user control
upstream backend {
    server 127.0.0.1:8080;
}

location /api/ {
    proxy_pass http://backend;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # Timeouts
    proxy_connect_timeout 60s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;
}
```

!!! success "Gixy Detection"
    Gixy's [`ssrf`](checks/ssrf.md) check detects proxy configurations where user input can control the destination.

---

## 9. Rate Limiting and DDoS Protection

**Risk Level:** Medium
**Attack Vector:** DoS, brute force, resource exhaustion

Implement rate limiting to protect against abuse and denial-of-service attacks.

### Hardened Configuration

```nginx
http {
    # Define rate limit zones
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    limit_conn_zone $binary_remote_addr zone=addr:10m;

    # Limit request body size
    client_max_body_size 10m;
    client_body_buffer_size 128k;

    # Limit header size
    large_client_header_buffers 4 16k;

    server {
        # General rate limiting
        limit_req zone=general burst=20 nodelay;
        limit_conn addr 10;

        # Stricter limits for login endpoints
        location /login {
            limit_req zone=login burst=5 nodelay;
        }
    }
}
```

---

## 10. Logging and Monitoring

**Risk Level:** Medium
**Attack Vector:** Missed attack detection, compliance failures

Proper logging is essential for security monitoring and incident response.

### Vulnerable Configuration

```nginx
http {
    error_log off;  # DANGEROUS: No error logging
}
```

### Hardened Configuration

```nginx
http {
    # Structured logging for security analysis
    log_format security '$remote_addr - $remote_user [$time_local] '
                        '"$request" $status $body_bytes_sent '
                        '"$http_referer" "$http_user_agent" '
                        '$request_time $upstream_response_time '
                        '$ssl_protocol $ssl_cipher';

    access_log /var/log/nginx/access.log security;
    error_log /var/log/nginx/error.log warn;

    server {
        # Log 4xx/5xx responses for security monitoring
        access_log /var/log/nginx/security.log security if=$loggable;
    }
}

# Define loggable variable
map $status $loggable {
    ~^[23]  0;
    default 1;
}
```

!!! success "Gixy Detection"
    Gixy's [`error_log_off`](checks/error-log-off.md) check detects dangerous configurations that disable error logging.

---

## 11. Disable Unnecessary Modules

**Risk Level:** Low-Medium
**Attack Vector:** Reduced attack surface

Compile NGINX with only the modules you need:

```bash
./configure \
    --without-http_autoindex_module \
    --without-http_ssi_module \
    --without-http_userid_module \
    --without-http_auth_basic_module \  # Only if not used
    --without-http_mirror_module
```

For pre-built packages, disable at runtime where possible:

```nginx
autoindex off;        # Disable directory listing
ssi off;              # Disable SSI if not needed
```

---

## 12. File Permissions and Ownership

**Risk Level:** Medium
**Attack Vector:** Privilege escalation, unauthorized modification

```bash
# Set proper ownership
chown -R root:root /etc/nginx
chown -R www-data:www-data /var/log/nginx

# Restrict configuration access
chmod 640 /etc/nginx/nginx.conf
chmod 750 /etc/nginx/conf.d
chmod 640 /etc/nginx/conf.d/*

# Protect SSL certificates
chmod 600 /etc/nginx/ssl/*.key
chmod 644 /etc/nginx/ssl/*.crt
```

---

## Complete Hardened Configuration Template

Here's a complete nginx.conf incorporating all the hardening measures above:

```nginx
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;

events {
    worker_connections 4096;
    multi_accept on;
    use epoll;
}

http {
    # Basic settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # Hide version
    server_tokens off;

    # MIME types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Rate limiting zones
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    limit_conn_zone $binary_remote_addr zone=addr:10m;

    # Request size limits
    client_max_body_size 10m;
    client_body_buffer_size 128k;
    large_client_header_buffers 4 16k;

    # SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;

    # Logging
    log_format security '$remote_addr - $remote_user [$time_local] '
                        '"$request" $status $body_bytes_sent '
                        '"$http_referer" "$http_user_agent"';

    access_log /var/log/nginx/access.log security;
    error_log /var/log/nginx/error.log warn;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript application/xml;

    # Default server to reject unknown hosts
    server {
        listen 80 default_server;
        listen 443 ssl default_server;
        server_name _;
        ssl_certificate /etc/nginx/ssl/dummy.crt;
        ssl_certificate_key /etc/nginx/ssl/dummy.key;
        return 444;
    }

    # Include site configurations
    include /etc/nginx/conf.d/*.conf;
}
```

---

## Verify Your Configuration with Gixy

After implementing these hardening measures, verify your configuration is secure:

```bash
# Install Gixy
pip install gixy-ng

# Scan your configuration
gixy /etc/nginx/nginx.conf

# Scan with all includes
gixy /etc/nginx/nginx.conf --config /etc/nginx/

# JSON output for CI/CD
gixy /etc/nginx/nginx.conf --format json
```

See the [CI/CD Integration Guide](ci-cd-integration.md) to automate security checks in your deployment pipeline.

---

## Next Steps

- [NGINX Security Checklist](nginx-security-checklist.md) - Quick reference checklist
- [Security Headers Deep Dive](nginx-security-headers.md) - Detailed header configuration guide
- [All Gixy Security Checks](index.md) - Complete list of automated checks
- [Try Gixy Online](https://www.getpagespeed.com/check-nginx-config) - Paste your config for instant analysis

--8<-- "en/snippets/nginx-extras-cta.md"
