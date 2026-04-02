---
title: "NGINX Security Headers Configuration Guide"
description: "Complete guide to configuring HTTP security headers in NGINX: HSTS, CSP, X-Frame-Options, CORS, and more. Copy-paste examples included."
keywords: "nginx security headers, nginx HSTS, nginx Content-Security-Policy, nginx X-Frame-Options, nginx CORS headers, nginx add_header"
---

# NGINX Security Headers Configuration

HTTP security headers are your first line of defense against client-side attacks like XSS, clickjacking, and data injection. This guide covers every security header you should configure in NGINX.

!!! warning "Critical: Header Inheritance in NGINX"
    When you use `add_header` in a child block (like `location`), it **completely overrides** all headers from parent blocks. This is the #1 cause of security header misconfigurations. Gixy can [detect this automatically](checks/add-header-redefinition.md).

---

## Quick Start: Essential Headers

Copy this block into your server configuration for immediate protection:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name example.com;

    # === ESSENTIAL SECURITY HEADERS ===

    # HSTS - Force HTTPS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Prevent clickjacking
    add_header X-Frame-Options "SAMEORIGIN" always;

    # Prevent MIME type sniffing
    add_header X-Content-Type-Options "nosniff" always;

    # XSS filter (legacy browsers)
    add_header X-XSS-Protection "1; mode=block" always;

    # Control referrer information
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Content Security Policy (customize for your app)
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; frame-ancestors 'self';" always;

    # Restrict browser features
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;

    # ... rest of your configuration
}
```

---

## Header Reference

### 1. Strict-Transport-Security (HSTS)

Forces browsers to use HTTPS for all future requests to your domain.

**Attack Prevented:** SSL stripping, protocol downgrade attacks

```nginx
# Basic - 1 year
add_header Strict-Transport-Security "max-age=31536000" always;

# Include subdomains
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Ready for preload list
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

| Directive | Description |
|-----------|-------------|
| `max-age` | Time in seconds browsers remember to use HTTPS |
| `includeSubDomains` | Apply to all subdomains |
| `preload` | Eligible for browser preload lists |

!!! danger "Before Using `includeSubDomains`"
    Ensure ALL subdomains have valid HTTPS. A broken subdomain will become completely inaccessible.

!!! tip "Rollout Strategy"
    1. Start with `max-age=300` (5 minutes)
    2. Increase to `max-age=86400` (1 day)
    3. Increase to `max-age=604800` (1 week)
    4. Finally set `max-age=31536000` (1 year)

:white_check_mark: **Gixy Check:** [`hsts_header`](checks/hsts-header.md)

---

### 2. Content-Security-Policy (CSP)

Controls what resources the browser can load. The most powerful security header.

**Attacks Prevented:** XSS, data injection, clickjacking

```nginx
# Strict CSP (breaks most sites - start here for new projects)
add_header Content-Security-Policy "default-src 'self'" always;

# Typical web application
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://api.example.com; frame-ancestors 'self';" always;

# Report-only mode (for testing)
add_header Content-Security-Policy-Report-Only "default-src 'self'; report-uri /csp-report" always;
```

**Common Directives:**

| Directive | Controls | Example |
|-----------|----------|---------|
| `default-src` | Fallback for other directives | `'self'` |
| `script-src` | JavaScript sources | `'self' https://cdn.com` |
| `style-src` | CSS sources | `'self' 'unsafe-inline'` |
| `img-src` | Image sources | `'self' data: https:` |
| `font-src` | Font sources | `'self' https://fonts.gstatic.com` |
| `connect-src` | XHR, WebSocket, fetch | `'self' https://api.example.com` |
| `frame-src` | Iframe sources | `'self'` |
| `frame-ancestors` | Who can embed this page | `'self'` |
| `base-uri` | Base URL restriction | `'self'` |
| `form-action` | Form submission targets | `'self'` |

**Source Values:**

| Value | Meaning |
|-------|---------|
| `'self'` | Same origin |
| `'none'` | Block all |
| `'unsafe-inline'` | Allow inline scripts/styles (avoid if possible) |
| `'unsafe-eval'` | Allow eval() (avoid) |
| `https:` | Any HTTPS URL |
| `data:` | Data URIs |
| `'nonce-{random}'` | Specific inline scripts with matching nonce |
| `'sha256-{hash}'` | Specific inline scripts with matching hash |

!!! tip "CSP Development Workflow"
    1. Start with `Content-Security-Policy-Report-Only`
    2. Monitor reports to identify needed sources
    3. Gradually tighten policy
    4. Switch to enforcing `Content-Security-Policy`

---

### 3. X-Frame-Options

Prevents your page from being embedded in iframes (clickjacking protection).

**Attack Prevented:** Clickjacking, UI redressing

```nginx
# Deny all framing
add_header X-Frame-Options "DENY" always;

# Allow same origin only
add_header X-Frame-Options "SAMEORIGIN" always;

# Allow specific origin (deprecated, use CSP frame-ancestors instead)
add_header X-Frame-Options "ALLOW-FROM https://trusted.com" always;
```

| Value | Description |
|-------|-------------|
| `DENY` | Cannot be framed by anyone |
| `SAMEORIGIN` | Can only be framed by same origin |
| `ALLOW-FROM uri` | Deprecated, use CSP instead |

!!! note "Modern Alternative"
    CSP's `frame-ancestors` directive is more flexible and widely supported:
    ```nginx
    add_header Content-Security-Policy "frame-ancestors 'self' https://trusted.com" always;
    ```

---

### 4. X-Content-Type-Options

Prevents MIME type sniffing attacks.

**Attack Prevented:** MIME confusion attacks, drive-by downloads

```nginx
add_header X-Content-Type-Options "nosniff" always;
```

Only one valid value: `nosniff`. Always use it.

---

### 5. X-XSS-Protection

Enables browser's built-in XSS filter. Mostly for legacy browsers.

**Attack Prevented:** Reflected XSS (in older browsers)

```nginx
add_header X-XSS-Protection "1; mode=block" always;
```

| Value | Description |
|-------|-------------|
| `0` | Disable filter |
| `1` | Enable filter (sanitize) |
| `1; mode=block` | Enable filter (block page) |

!!! note "Modern Browsers"
    Modern browsers have deprecated this header in favor of CSP. Still useful for IE11 and older browser support.

---

### 6. Referrer-Policy

Controls how much referrer information is sent with requests.

**Attack Prevented:** Information leakage, privacy violations

```nginx
# Recommended for most sites
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Maximum privacy
add_header Referrer-Policy "no-referrer" always;

# Same-origin only
add_header Referrer-Policy "same-origin" always;
```

| Value | Same-origin | Cross-origin (HTTPS→HTTPS) | Cross-origin (HTTPS→HTTP) |
|-------|-------------|---------------------------|---------------------------|
| `no-referrer` | None | None | None |
| `same-origin` | Full URL | None | None |
| `strict-origin` | Origin only | Origin only | None |
| `strict-origin-when-cross-origin` | Full URL | Origin only | None |
| `origin-when-cross-origin` | Full URL | Origin only | Origin only |

---

### 7. Permissions-Policy (formerly Feature-Policy)

Restricts access to browser features and APIs.

**Attack Prevented:** Unwanted feature access, privacy violations

```nginx
# Disable all sensitive features
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()" always;

# Allow specific features for same origin
add_header Permissions-Policy "geolocation=(self), camera=(self), microphone=()" always;

# Allow features for specific origins
add_header Permissions-Policy "geolocation=(self https://maps.example.com)" always;
```

**Common Features:**

| Feature | Description |
|---------|-------------|
| `geolocation` | GPS/location access |
| `camera` | Camera access |
| `microphone` | Microphone access |
| `payment` | Payment Request API |
| `usb` | USB device access |
| `fullscreen` | Fullscreen API |
| `autoplay` | Media autoplay |
| `display-capture` | Screen capture |

---

### 8. Cross-Origin Headers

Control cross-origin resource access.

#### Cross-Origin-Embedder-Policy (COEP)

```nginx
# Require CORS/CORP for all resources
add_header Cross-Origin-Embedder-Policy "require-corp" always;

# Credentialless mode
add_header Cross-Origin-Embedder-Policy "credentialless" always;
```

#### Cross-Origin-Opener-Policy (COOP)

```nginx
# Isolate browsing context
add_header Cross-Origin-Opener-Policy "same-origin" always;

# Allow popups but isolate
add_header Cross-Origin-Opener-Policy "same-origin-allow-popups" always;
```

#### Cross-Origin-Resource-Policy (CORP)

```nginx
# Only same-origin can load this resource
add_header Cross-Origin-Resource-Policy "same-origin" always;

# Same-site can load
add_header Cross-Origin-Resource-Policy "same-site" always;

# Any origin can load
add_header Cross-Origin-Resource-Policy "cross-origin" always;
```

!!! info "When You Need These"
    These headers are required for features like `SharedArrayBuffer` and high-resolution timers. Most sites don't need them.

---

## CORS Configuration

For APIs that need to accept cross-origin requests:

```nginx
# Simple CORS - allow all origins (public APIs only)
location /api/ {
    add_header Access-Control-Allow-Origin "*" always;
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;

    if ($request_method = OPTIONS) {
        return 204;
    }
}

# Specific origin CORS
location /api/ {
    set $cors_origin "";
    if ($http_origin ~* "^https://(www\.)?example\.com$") {
        set $cors_origin $http_origin;
    }

    add_header Access-Control-Allow-Origin $cors_origin always;
    add_header Access-Control-Allow-Credentials "true" always;
    add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Content-Type, Authorization, X-Requested-With" always;
    add_header Access-Control-Max-Age "86400" always;

    if ($request_method = OPTIONS) {
        return 204;
    }
}
```

!!! danger "Never Use `*` with Credentials"
    `Access-Control-Allow-Origin: *` cannot be used with `Access-Control-Allow-Credentials: true`. This is a browser security restriction.

---

## Solving the Header Inheritance Problem

### The Problem

```nginx
server {
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    location /api {
        add_header Access-Control-Allow-Origin "*" always;
        # X-Frame-Options and X-Content-Type-Options are now GONE!
    }
}
```

### Solution 1: Use `include` for Common Headers

```nginx
# /etc/nginx/snippets/security-headers.conf
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

```nginx
server {
    include /etc/nginx/snippets/security-headers.conf;

    location /api {
        include /etc/nginx/snippets/security-headers.conf;
        add_header Access-Control-Allow-Origin "*" always;
    }
}
```

### Solution 2: Use `headers-more` Module

```nginx
# Set headers at http level that won't be overridden
more_set_headers "X-Frame-Options: SAMEORIGIN";
more_set_headers "X-Content-Type-Options: nosniff";
```

### Solution 3: Use `map` for Dynamic Headers

```nginx
http {
    map $uri $security_headers {
        default "SAMEORIGIN";
        ~^/embed "ALLOW-FROM https://trusted.com";
    }

    server {
        add_header X-Frame-Options $security_headers always;
    }
}
```

:white_check_mark: **Gixy Check:** Gixy's [`add_header_redefinition`](checks/add-header-redefinition.md) automatically detects when headers defined in parent blocks are accidentally cleared in child blocks.

---

## Complete Configuration Example

```nginx
http {
    # === GLOBAL SECURITY HEADERS ===
    # Applied to all servers unless overridden

    # Note: These will be cleared if any location uses add_header
    # Use the include pattern for consistent application

    server {
        listen 443 ssl;
        http2 on;
        server_name example.com;

        # SSL Configuration
        ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;

        # Include security headers in every context
        include /etc/nginx/snippets/security-headers.conf;

        root /var/www/example.com;
        index index.html;

        location / {
            include /etc/nginx/snippets/security-headers.conf;
            try_files $uri $uri/ =404;
        }

        location /api/ {
            include /etc/nginx/snippets/security-headers.conf;

            # API-specific headers
            add_header Access-Control-Allow-Origin "https://app.example.com" always;
            add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE" always;

            proxy_pass http://backend;
        }

        location /embed/ {
            include /etc/nginx/snippets/security-headers.conf;

            # Override frame policy for embed endpoint
            add_header X-Frame-Options "" always;  # Clear default
            add_header Content-Security-Policy "frame-ancestors https://partner.com" always;
        }
    }
}
```

**`/etc/nginx/snippets/security-headers.conf`:**

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

---

## Testing Your Headers

### Online Tools

- [SecurityHeaders.com](https://securityheaders.com/) — Comprehensive header analysis
- [Mozilla Observatory](https://observatory.mozilla.org/) — Security assessment
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/) — CSP policy analysis

### Command Line

```bash
# Check all response headers
curl -I https://example.com

# Check specific header
curl -s -I https://example.com | grep -i "strict-transport"

# Check with verbose output
curl -v https://example.com 2>&1 | grep -i "< "
```

### Browser DevTools

1. Open DevTools (F12)
2. Go to Network tab
3. Click on any request
4. View Response Headers

---

## Common Mistakes

### 1. Forgetting `always`

```nginx
# BAD: Only added on successful responses
add_header X-Frame-Options "SAMEORIGIN";

# GOOD: Added on all responses including errors
add_header X-Frame-Options "SAMEORIGIN" always;
```

### 2. Using Wrong CSP on APIs

```nginx
# BAD: CSP with 'self' blocks API responses
location /api/ {
    add_header Content-Security-Policy "default-src 'self'" always;
}

# GOOD: Different or no CSP for APIs
location /api/ {
    # APIs typically don't need CSP
}
```

### 3. HSTS on HTTP

```nginx
# BAD: HSTS on port 80 (useless and weird)
server {
    listen 80;
    add_header Strict-Transport-Security "max-age=31536000" always;
}

# GOOD: HSTS only on HTTPS
server {
    listen 443 ssl;
    add_header Strict-Transport-Security "max-age=31536000" always;
}
```

---

## Related Resources

- [Complete NGINX Hardening Guide](nginx-hardening-guide.md)
- [NGINX Security Checklist](nginx-security-checklist.md)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)

--8<-- "en/snippets/nginx-extras-cta.md"
