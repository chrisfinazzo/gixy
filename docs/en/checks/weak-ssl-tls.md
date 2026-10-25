---
title: "Weak SSL/TLS Configuration"
description: "Shut off legacy TLS and weak ciphers in NGINX. Move to modern Mozilla-style suites to avoid POODLE/BEAST/Sweet32."
---

# Weak SSL/TLS Configuration

_Gixy Check ID: `weak_ssl_tls`_


## Overview

The `weak_ssl_tls` plugin detects insecure SSL/TLS configurations that may compromise the security of encrypted connections. This includes outdated protocols, weak cipher suites, and client-driven cipher selection.

## What it detects

### 1. Insecure TLS Protocols
Detects use of deprecated protocols that are vulnerable to attacks:

| Protocol | Status | Vulnerabilities |
|----------|--------|-----------------|
| SSLv2 | ❌ Insecure | Multiple critical flaws |
| SSLv3 | ❌ Insecure | POODLE attack |
| TLSv1.0 | ❌ Insecure | BEAST, POODLE, CRIME |
| TLSv1.1 | ❌ Insecure | Weak ciphers, no AEAD |
| TLSv1.2 | ✅ Secure | Use with strong ciphers |
| TLSv1.3 | ✅ Secure | Modern, recommended |

### 2. Weak Cipher Suites
Detects cipher suites that should be avoided:

`ssl_ciphers` is evaluated as an ordered OpenSSL expression: `!` permanently
excludes, `-` removes until later re-added, a leading `+` only reorders, and
an interior `+` intersects selectors. Broad or unknown selectors may produce
a **possible weak selection** warning when their full suite membership cannot
be proved from configuration. The scanner does not use the host OpenSSL build
to dismiss a suite that may exist on the target server. See the
[OpenSSL cipher-string syntax](https://docs.openssl.org/3.5/man1/openssl-ciphers/).

- **NULL ciphers** - No encryption at all
- **EXPORT ciphers** - Intentionally weakened (40-56 bit)
- **DES/3DES** - Vulnerable to Sweet32 attack
- **RC4** - Broken stream cipher
- **Anonymous ciphers (ADH/AECDH)** - No authentication
- **MD5-based ciphers** - Weak hash function

### 3. Server Cipher Preference
Detects when `ssl_prefer_server_ciphers` is set to `on`. With modern cipher lists containing only strong AEAD ciphers, server cipher preference is unnecessary and may hurt performance — mobile clients without AES-NI hardware benefit from choosing ChaCha20-Poly1305 over AES-GCM. Both [Mozilla](https://ssl-config.mozilla.org/) and nginx maintainers recommend `off`.

**Exception:** This check is suppressed when `ssl_conf_command Options PrioritizeChaCha` is also configured. OpenSSL's `SSL_OP_PRIORITIZE_CHACHA` (available since OpenSSL 1.1.1) automatically prefers ChaCha20-Poly1305 for clients that signal preference for it, while still letting the server control cipher ordering for other clients. This is a well-known pattern that addresses the underlying concern.

## Examples

### ❌ Bad: Insecure protocols enabled
```nginx
server {
    listen 443 ssl;
    ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;  # SSLv3, TLSv1, TLSv1.1 are insecure
}
```
**Issue**: `Insecure protocols enabled: SSLv3, TLSv1, TLSv1.1`

### ❌ Bad: Weak ciphers
```nginx
server {
    listen 443 ssl;
    ssl_ciphers ALL:RC4:DES:3DES;  # Includes weak ciphers
}
```
**Issue**: `Weak ciphers found: RC4, DES, 3DES`

### ❌ Bad: Server cipher preference enabled
```nginx
server {
    listen 443 ssl;
    ssl_prefer_server_ciphers on;  # Unnecessary with modern cipher lists
}
```
**Issue**: `Server cipher preference enabled unnecessarily` (LOW)

### ✅ Good: Server cipher preference with PrioritizeChaCha
```nginx
server {
    listen 443 ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_conf_command Options PrioritizeChaCha;
}
```
No issue — `PrioritizeChaCha` ensures ChaCha20 is preferred for clients that need it.

### ✅ Good: Secure configuration
```nginx
server {
    listen 443 ssl;

    # Modern protocols only
    ssl_protocols TLSv1.2 TLSv1.3;

    # Mozilla Intermediate cipher suite
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    # Client chooses cipher (recommended by Mozilla)
    ssl_prefer_server_ciphers off;

    # HSTS is checked by the dedicated `hsts_header` plugin.
}
```

## Recommended Configuration

Based on [Mozilla's SSL Configuration Generator](https://ssl-config.mozilla.org/):

### Intermediate Configuration (Recommended)
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
```

### Modern Configuration (TLSv1.3 only)
```nginx
ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers off;
```

## Why This Matters

Weak SSL/TLS configurations expose your server to:

1. **POODLE Attack** (SSLv3) - Allows decryption of secure connections
2. **BEAST Attack** (TLSv1.0) - Allows decryption of HTTPS cookies
3. **Sweet32 Attack** (3DES) - Allows recovery of plaintext from long connections
4. **RC4 Bias** - Allows plaintext recovery from encrypted streams
5. **Downgrade Attacks** - Force use of weaker protocols

## Testing Your Configuration

Use these tools to verify your SSL/TLS configuration:

- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- `openssl s_client -connect yoursite.com:443`

## References

- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [Mozilla Server Side TLS Guide](https://wiki.mozilla.org/Security/Server_Side_TLS)
- [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)

--8<-- "en/snippets/nginx-extras-cta.md"
