---
title: "NGINX 安全加固完整指南 2026"
description: "NGINX 安全加固分步指南。涵盖 SSL/TLS、安全头、访问控制、速率限制等内容。使用 Gixy 自动化检查。"
keywords: "nginx 加固, nginx 安全, nginx 加固指南, nginx 安全最佳实践, nginx 加固清单, nginx 安全配置"
---

# NGINX 安全加固完整指南

本综合指南涵盖了加固 NGINX 服务器以抵御常见攻击和配置错误所需的全部内容。每个部分都包括漏洞说明、修复方法以及 Gixy 如何自动检测该问题。

!!! tip "自动化安全检查"
    无需手动审计您的 nginx.conf——运行 `gixy /etc/nginx/nginx.conf` 即可自动捕获这些问题。[开始使用 →](index.md)

---

## 1. 隐藏 NGINX 版本信息

**风险级别：** 中等
**攻击向量：** 信息泄露帮助攻击者针对已知 CVE 进行攻击

默认情况下，NGINX 会在 HTTP 响应头和错误页面中暴露其版本号。这有助于攻击者确定哪些漏洞适用于您的服务器。

### 易受攻击的配置

```nginx
http {
    # 如果未指定，server_tokens 默认为 'on'
    server {
        listen 80;
        server_name example.com;
    }
}
```

响应头：`Server: nginx/1.24.0`

### 加固后的配置

```nginx
http {
    server_tokens off;  # 在响应头和错误页面中隐藏版本

    server {
        listen 80;
        server_name example.com;
    }
}
```

响应头：`Server: nginx`

!!! success "Gixy 检测"
    Gixy 的 [`version_disclosure`](checks/version-disclosure.md) 检查会自动检测显式的 `server_tokens on;` 以及默认导致版本泄露的缺失指令。

---

## 2. 配置安全的 SSL/TLS

**风险级别：** 严重
**攻击向量：** POODLE、BEAST、Sweet32、降级攻击

薄弱的 SSL/TLS 配置可能允许攻击者解密流量或执行中间人攻击。

### 易受攻击的配置

```nginx
server {
    listen 443 ssl;
    ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;  # 过时的协议
    ssl_ciphers ALL;  # 包含弱加密套件
}
```

### 加固后的配置（Mozilla 中级）

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name example.com;

    # 仅使用现代协议
    ssl_protocols TLSv1.2 TLSv1.3;

    # 强加密套件（Mozilla 中级）
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

!!! success "Gixy 检测"
    Gixy 的 [`weak_ssl_tls`](checks/weak-ssl-tls.md) 检查可检测不安全的协议（SSLv2、SSLv3、TLSv1.0、TLSv1.1）和弱加密套件（RC4、DES、3DES、EXPORT、NULL）。

---

## 3. 启用 HTTP 严格传输安全（HSTS）

**风险级别：** 高
**攻击向量：** SSL 剥离、降级攻击

HSTS 告诉浏览器始终使用 HTTPS，防止 SSL 剥离攻击。

### 易受攻击的配置

```nginx
server {
    listen 443 ssl;
    # 缺少 HSTS 头 - 容易受到 SSL 剥离攻击
}
```

### 加固后的配置

```nginx
server {
    listen 443 ssl http2;

    # HSTS，max-age 为 1 年并包含子域
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}
```

!!! warning "HSTS 注意事项"
    - 测试期间从较短的 `max-age`（例如 300）开始
    - 只有在准备好提交到 [HSTS 预加载列表](https://hstspreload.org/) 时才添加 `preload`
    - 在使用 `includeSubDomains` 之前确保所有子域都支持 HTTPS

!!! success "Gixy 检测"
    Gixy 的 [`hsts_header`](checks/hsts-header.md) 检查可检测 HTTPS 服务器上缺失或配置错误的 HSTS 头。

---

## 4. 添加安全头

**风险级别：** 中高
**攻击向量：** XSS、点击劫持、MIME 嗅探攻击

安全头提供针对各种客户端攻击的纵深防御。

### 加固后的配置

```nginx
server {
    listen 443 ssl http2;

    # 防止点击劫持
    add_header X-Frame-Options "SAMEORIGIN" always;

    # 防止 MIME 类型嗅探
    add_header X-Content-Type-Options "nosniff" always;

    # XSS 保护（旧版浏览器）
    add_header X-XSS-Protection "1; mode=block" always;

    # Referrer 策略
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # 内容安全策略（根据您的应用自定义）
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;

    # 权限策略
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
}
```

!!! danger "头部继承警告"
    NGINX 中子块（如 `location`）中的 `add_header` 指令会**完全覆盖**父块的头部。如果您在 location 块中添加任何头部，必须重新添加所有安全头部。

!!! success "Gixy 检测"
    Gixy 的 [`add_header_redefinition`](checks/add-header-redefinition.md) 检查可检测子块意外清除父块中定义的安全头部的情况。

---

## 5. 防止 Host 头欺骗

**风险级别：** 高
**攻击向量：** 缓存投毒、密码重置投毒、SSRF

如果没有拒绝未知主机的默认服务器，攻击者可以发送带有任意 Host 头的请求。

### 易受攻击的配置

```nginx
server {
    listen 80;
    server_name example.com;
    # 第一个 server 块成为默认 - 接受任何 Host 头
}
```

### 加固后的配置

```nginx
# 拒绝未知主机的默认服务器
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    server_name _;

    ssl_certificate /path/to/dummy.crt;
    ssl_certificate_key /path/to/dummy.key;

    return 444;  # 关闭连接而不响应
}

# 您的实际服务器
server {
    listen 80;
    listen 443 ssl;
    server_name example.com www.example.com;
    # ... 您的配置
}
```

!!! success "Gixy 检测"
    Gixy 的 [`host_spoofing`](checks/host-spoofing.md) 和 [`default_server_flag`](checks/default-server-flag.md) 检查可检测缺失的默认服务器配置和潜在的 Host 头攻击。

---

## 6. 实施访问控制

**风险级别：** 高
**攻击向量：** 未授权访问、信息泄露

限制对敏感位置的访问，并始终使用完整的 allow/deny 规则。

### 易受攻击的配置

```nginx
location /admin {
    allow 192.168.1.0/24;
    # 缺少 'deny all' - 其他 IP 仍然可以访问！
}
```

### 加固后的配置

```nginx
# 限制管理区域
location /admin {
    allow 10.0.0.0/8;
    allow 192.168.1.0/24;
    deny all;  # 始终以 deny all 结尾
}

# 阻止访问敏感文件
location ~ /\. {
    deny all;
}

location ~* \.(git|svn|env|htaccess|htpasswd)$ {
    deny all;
}

# 阻止访问备份文件
location ~* \.(bak|backup|old|orig|save|swp|tmp)$ {
    deny all;
}
```

!!! success "Gixy 检测"
    Gixy 的 [`allow_without_deny`](checks/allow-without-deny.md) 检查可检测不以 `deny all` 结尾的不完整访问控制规则。

---

## 7. 防止 Alias 路径遍历

**风险级别：** 严重
**攻击向量：** 目录遍历、任意文件读取

当 location 不以 `/` 结尾时，`alias` 指令容易出现路径遍历漏洞。

### 易受攻击的配置

```nginx
location /static {
    alias /var/www/static/;  # 易受攻击：location 中缺少尾部斜杠
}
```

攻击：`GET /static../etc/passwd` → 读取 `/var/www/static/../etc/passwd` → `/var/www/etc/passwd`

### 加固后的配置

```nginx
# 选项 1：在 location 中添加尾部斜杠
location /static/ {
    alias /var/www/static/;
}

# 选项 2：使用 root 代替 alias
location /static/ {
    root /var/www;
}
```

!!! success "Gixy 检测"
    Gixy 的 [`alias_traversal`](checks/alias-traversal.md) 检查可检测易受路径遍历攻击的 alias 配置。

---

## 8. 安全的代理配置

**风险级别：** 严重
**攻击向量：** SSRF、HTTP 请求走私

配置不当的反向代理可能允许服务器端请求伪造（SSRF）攻击。

### 易受攻击的配置

```nginx
# SSRF 漏洞 - 攻击者控制代理目标
location ~ /proxy/(.*)/(.*)/(.*)$ {
    proxy_pass $1://$2/$3;
}
```

### 加固后的配置

```nginx
# 硬编码的上游 - 无用户控制
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

    # 超时
    proxy_connect_timeout 60s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;
}
```

!!! success "Gixy 检测"
    Gixy 的 [`ssrf`](checks/ssrf.md) 检查可检测用户输入可以控制目标的代理配置。

---

## 9. 速率限制和 DDoS 防护

**风险级别：** 中等
**攻击向量：** DoS、暴力破解、资源耗尽

实施速率限制以防止滥用和拒绝服务攻击。

### 加固后的配置

```nginx
http {
    # 定义速率限制区域
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    limit_conn_zone $binary_remote_addr zone=addr:10m;

    # 限制请求体大小
    client_max_body_size 10m;
    client_body_buffer_size 128k;

    # 限制头部大小
    large_client_header_buffers 4 16k;

    server {
        # 通用速率限制
        limit_req zone=general burst=20 nodelay;
        limit_conn addr 10;

        # 登录端点的更严格限制
        location /login {
            limit_req zone=login burst=5 nodelay;
        }
    }
}
```

---

## 10. 日志记录和监控

**风险级别：** 中等
**攻击向量：** 错过攻击检测、合规性失败

适当的日志记录对于安全监控和事件响应至关重要。

### 易受攻击的配置

```nginx
http {
    error_log off;  # 危险：无错误日志
}
```

### 加固后的配置

```nginx
http {
    # 用于安全分析的结构化日志
    log_format security '$remote_addr - $remote_user [$time_local] '
                        '"$request" $status $body_bytes_sent '
                        '"$http_referer" "$http_user_agent" '
                        '$request_time $upstream_response_time '
                        '$ssl_protocol $ssl_cipher';

    access_log /var/log/nginx/access.log security;
    error_log /var/log/nginx/error.log warn;

    server {
        # 记录 4xx/5xx 响应用于安全监控
        access_log /var/log/nginx/security.log security if=$loggable;
    }
}

# 定义 loggable 变量
map $status $loggable {
    ~^[23]  0;
    default 1;
}
```

!!! success "Gixy 检测"
    Gixy 的 [`error_log_off`](checks/error-log-off.md) 检查可检测禁用错误日志的危险配置。

---

## 11. 禁用不必要的模块

**风险级别：** 低-中
**攻击向量：** 减少攻击面

仅使用您需要的模块编译 NGINX：

```bash
./configure \
    --without-http_autoindex_module \
    --without-http_ssi_module \
    --without-http_userid_module \
    --without-http_auth_basic_module \  # 仅在不使用时
    --without-http_mirror_module
```

对于预构建的软件包，在可能的情况下在运行时禁用：

```nginx
autoindex off;        # 禁用目录列表
ssi off;              # 如不需要则禁用 SSI
```

---

## 12. 文件权限和所有权

**风险级别：** 中等
**攻击向量：** 权限提升、未授权修改

```bash
# 设置正确的所有权
chown -R root:root /etc/nginx
chown -R www-data:www-data /var/log/nginx

# 限制配置访问
chmod 640 /etc/nginx/nginx.conf
chmod 750 /etc/nginx/conf.d
chmod 640 /etc/nginx/conf.d/*

# 保护 SSL 证书
chmod 600 /etc/nginx/ssl/*.key
chmod 644 /etc/nginx/ssl/*.crt
```

---

## 完整的加固配置模板

这是一个包含上述所有加固措施的完整 nginx.conf：

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
    # 基本设置
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # 隐藏版本
    server_tokens off;

    # MIME 类型
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # 速率限制区域
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    limit_conn_zone $binary_remote_addr zone=addr:10m;

    # 请求大小限制
    client_max_body_size 10m;
    client_body_buffer_size 128k;
    large_client_header_buffers 4 16k;

    # SSL 设置
    # SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;

    # 日志记录
    log_format security '$remote_addr - $remote_user [$time_local] '
                        '"$request" $status $body_bytes_sent '
                        '"$http_referer" "$http_user_agent"';

    access_log /var/log/nginx/access.log security;
    error_log /var/log/nginx/error.log warn;

    # Gzip 压缩
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript application/xml;

    # 拒绝未知主机的默认服务器
    server {
        listen 80 default_server;
        listen 443 ssl default_server;
        server_name _;
        ssl_certificate /etc/nginx/ssl/dummy.crt;
        ssl_certificate_key /etc/nginx/ssl/dummy.key;
        return 444;
    }

    # 包含站点配置
    include /etc/nginx/conf.d/*.conf;
}
```

---

## 使用 Gixy 验证您的配置

实施这些加固措施后，验证您的配置是否安全：

```bash
# 安装 Gixy
pip install gixy-ng

# 扫描您的配置
gixy /etc/nginx/nginx.conf

# 扫描包含所有 include 的配置
gixy /etc/nginx/nginx.conf --config /etc/nginx/

# CI/CD 的 JSON 输出
gixy /etc/nginx/nginx.conf --format json
```

请参阅 [CI/CD 集成指南](ci-cd-integration.md) 在您的部署流水线中自动化安全检查。

---

## 下一步

- [NGINX 安全检查清单](nginx-security-checklist.md) - 快速参考清单
- [安全头深入解析](nginx-security-headers.md) - 详细的头部配置指南
- [所有 Gixy 安全检查](index.md) - 完整的自动化检查列表
- [在线试用 Gixy](https://www.getpagespeed.com/check-nginx-config) - 粘贴您的配置进行即时分析

--8<-- "zh/snippets/nginx-extras-cta.md"
