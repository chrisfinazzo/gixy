---
title: "NGINX 安全检查清单 2026"
description: "可打印的 NGINX 安全加固检查清单。40 多项可操作项目，涵盖 SSL/TLS、安全头、访问控制和配置最佳实践。"
keywords: "nginx 安全检查清单, nginx 加固清单, nginx 安全审计, nginx 安全最佳实践, nginx 配置检查清单"
---

# NGINX 安全检查清单

一个全面、可操作的检查清单，用于保护您的 NGINX 服务器。用于安全审计、合规性审查或加固新部署。

!!! tip "自动化此检查清单"
    无需手动检查每个项目，运行 `gixy /etc/nginx/nginx.conf` 即可自动检测许多这些问题。[了解更多 →](index.md)

---

## 版本和信息泄露

- [ ] **隐藏 NGINX 版本** — 在 http 块中设置 `server_tokens off;`
- [ ] **自定义错误页面** — 替换可能泄露版本信息的默认错误页面
- [ ] **移除 Server 头** — 使用 `more_clear_headers Server;`（需要 headers-more 模块）
- [ ] **隐藏 PHP 版本** — 在 php.ini 中设置 `expose_php = Off`

??? example "配置"
    ```nginx
    http {
        server_tokens off;

        # 自定义错误页面
        error_page 404 /custom_404.html;
        error_page 500 502 503 504 /custom_50x.html;
    }
    ```

:white_check_mark: **Gixy 检查：** [`version_disclosure`](checks/version-disclosure.md)

---

## SSL/TLS 配置

- [ ] **禁用旧协议** — 仅允许 TLSv1.2 和 TLSv1.3
- [ ] **使用强加密套件** — 遵循 Mozilla 中级或现代配置
- [ ] **禁用弱加密套件** — 无 RC4、DES、3DES、EXPORT、NULL 加密
- [ ] **启用 OCSP 装订** — 减少延迟并提高隐私
- [ ] **配置会话恢复** — 使用 `ssl_session_cache` 和 `ssl_session_tickets`
- [ ] **使用 2048+ 位 DH 参数** — 使用 `openssl dhparam -out dhparam.pem 4096` 生成
- [ ] **有效证书** — 检查过期时间、证书链完整性

??? example "配置"
    ```nginx
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ```

:white_check_mark: **Gixy 检查：** [`weak_ssl_tls`](checks/weak-ssl-tls.md)

---

## 安全头

- [ ] **启用 HSTS** — 带有适当 max-age 的 `Strict-Transport-Security`
- [ ] **X-Frame-Options** — 设置为 `DENY` 或 `SAMEORIGIN`
- [ ] **X-Content-Type-Options** — 设置为 `nosniff`
- [ ] **X-XSS-Protection** — 设置为 `1; mode=block`
- [ ] **Referrer-Policy** — 为您的用例设置适当的策略
- [ ] **Content-Security-Policy** — 定义允许的内容来源
- [ ] **Permissions-Policy** — 限制浏览器功能访问
- [ ] **所有上下文中的头部** — 验证头部不会在 location 块中丢失

??? example "配置"
    ```nginx
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self';" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    ```

:white_check_mark: **Gixy 检查：** [`hsts_header`](checks/hsts-header.md)、[`add_header_redefinition`](checks/add-header-redefinition.md)

---

## 主机和服务器配置

- [ ] **定义默认服务器** — 拒绝发送到未知 Host 头的请求
- [ ] **默认服务器返回 444** — 关闭连接而不响应
- [ ] **每个虚拟主机有显式 server_name** — 无通配符配置
- [ ] **HTTP 到 HTTPS 重定向** — 将所有 HTTP 流量重定向到 HTTPS
- [ ] **生产环境中无通配符 server_name** — 使用显式主机名

??? example "配置"
    ```nginx
    # 默认通配符服务器
    server {
        listen 80 default_server;
        listen 443 ssl default_server;
        server_name _;
        ssl_certificate /etc/nginx/ssl/dummy.crt;
        ssl_certificate_key /etc/nginx/ssl/dummy.key;
        return 444;
    }

    # HTTP 到 HTTPS 重定向
    server {
        listen 80;
        server_name example.com;
        return 301 https://$server_name$request_uri;
    }
    ```

:white_check_mark: **Gixy 检查：** [`host_spoofing`](checks/host-spoofing.md)、[`default_server_flag`](checks/default-server-flag.md)

---

## 访问控制

- [ ] **完整的 allow/deny 规则** — 每个 `allow` 块以 `deny all;` 结尾
- [ ] **保护敏感文件** — 阻止访问 `.git`、`.env`、`.htaccess` 等
- [ ] **保护备份文件** — 阻止 `.bak`、`.old`、`.swp`、`.tmp` 文件
- [ ] **管理区域受限** — 通过 IP 或认证限制访问
- [ ] **上传目录限制** — 在上传路径中禁用 PHP/脚本执行
- [ ] **return 不绕过访问控制** — 注意指令处理顺序

??? example "配置"
    ```nginx
    # 阻止敏感文件
    location ~ /\. {
        deny all;
    }

    location ~* \.(git|svn|env|htaccess|htpasswd)$ {
        deny all;
    }

    # 管理区域
    location /admin {
        allow 10.0.0.0/8;
        deny all;
        auth_basic "Admin Area";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }

    # 上传 - 无脚本执行
    location /uploads {
        location ~ \.(php|py|pl|cgi)$ {
            deny all;
        }
    }
    ```

:white_check_mark: **Gixy 检查：** [`allow_without_deny`](checks/allow-without-deny.md)、[`return_bypasses_allow_deny`](checks/return-bypasses-allow-deny.md)

---

## 路径和文件处理

- [ ] **Alias 尾部斜杠** — 使用 `alias` 的 location 必须以 `/` 结尾
- [ ] **无用户控制的路径** — 不要在文件路径中插入用户输入
- [ ] **验证 root 与 alias** — 理解其区别
- [ ] **限制 try_files 范围** — 小心 `try_files` 和用户输入

??? example "配置"
    ```nginx
    # 正确：两者都有尾部斜杠
    location /static/ {
        alias /var/www/static/;
    }

    # 替代方案：使用 root
    location /static/ {
        root /var/www;
    }
    ```

:white_check_mark: **Gixy 检查：** [`alias_traversal`](checks/alias-traversal.md)、[`try_files_is_evil_too`](checks/try-files-is-evil-too.md)

---

## 代理配置

- [ ] **无用户控制的 proxy_pass** — 硬编码上游服务器
- [ ] **内部 location 受保护** — 使用 `internal;` 指令
- [ ] **正确的头部转发** — 设置 Host、X-Real-IP、X-Forwarded-For
- [ ] **超时限制** — 配置连接、发送、读取超时
- [ ] **变量需要配置 resolver** — 在 proxy_pass 中使用变量时必需

??? example "配置"
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

:white_check_mark: **Gixy 检查：** [`ssrf`](checks/ssrf.md)、[`missing_resolver`](checks/missing-resolver.md)、[`proxy_pass_normalized`](checks/proxy-pass-normalized.md)

---

## 速率限制和 DoS 防护

- [ ] **连接限制** — 使用 `limit_conn_zone` 和 `limit_conn`
- [ ] **请求速率限制** — 使用 `limit_req_zone` 和 `limit_req`
- [ ] **认证端点的更严格限制** — 登录、注册的更低速率
- [ ] **请求体大小限制** — 设置适当的 `client_max_body_size`
- [ ] **头部缓冲区限制** — 配置 `large_client_header_buffers`
- [ ] **超时值** — 设置合理的 client_body_timeout、client_header_timeout

??? example "配置"
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

## 日志记录和监控

- [ ] **启用错误日志** — 永远不要使用 `error_log off;`
- [ ] **启用访问日志** — 记录所有请求的有用信息
- [ ] **面向安全的日志格式** — 包括客户端 IP、用户代理、响应时间
- [ ] **配置日志轮转** — 使用 logrotate 管理日志文件
- [ ] **日志监控就位** — 转发到 SIEM 或监控系统

??? example "配置"
    ```nginx
    log_format security '$remote_addr - $remote_user [$time_local] '
                        '"$request" $status $body_bytes_sent '
                        '"$http_referer" "$http_user_agent" '
                        '$request_time $upstream_response_time';

    access_log /var/log/nginx/access.log security;
    error_log /var/log/nginx/error.log warn;
    ```

:white_check_mark: **Gixy 检查：** [`error_log_off`](checks/error-log-off.md)

---

## 配置卫生

- [ ] **location 块中避免 `if`** — 尽可能使用 `map` 或 `try_files`
- [ ] **有效的正则表达式模式** — 使用 `nginx -t` 测试所有正则表达式
- [ ] **锚定的正则表达式** — 使用 `^` 和 `$` 防止部分匹配
- [ ] **无 ReDoS 漏洞** — 避免灾难性回溯
- [ ] **正确的 map 默认值** — 始终在 map 块中定义默认值
- [ ] **配置中的注释** — 记录非显而易见的配置

:white_check_mark: **Gixy 检查：** [`if_is_evil`](checks/if-is-evil.md)、[`invalid_regex`](checks/invalid-regex.md)、[`unanchored_regex`](checks/unanchored-regex.md)、[`regex_redos`](checks/regex-redos.md)、[`hash_without_default`](checks/hash-without-default.md)

---

## 性能和资源限制

- [ ] **Worker 进程** — 设置为 `auto` 或 CPU 核心数
- [ ] **Worker 连接** — 根据预期负载设置（通常 1024-4096）
- [ ] **文件描述符限制** — 确保 `worker_rlimit_nofile` 与系统限制匹配
- [ ] **Keepalive 调优** — 设置适当的 `keepalive_timeout` 和 `keepalive_requests`
- [ ] **启用 Gzip** — 压缩基于文本的响应
- [ ] **缓冲区调优** — 优化代理和 fastcgi 缓冲区

:white_check_mark: **Gixy 检查：** [`worker_rlimit_nofile_vs_connections`](checks/worker-rlimit-nofile-vs-connections.md)、[`low_keepalive_requests`](checks/low-keepalive-requests.md)

---

## 文件系统安全

- [ ] **配置文件权限** — `chmod 640 /etc/nginx/nginx.conf`
- [ ] **私钥权限** — SSL 私钥使用 `chmod 600`
- [ ] **所有权** — 配置由 root 拥有，日志由 www-data 拥有
- [ ] **SELinux/AppArmor** — 如果启用则配置 MAC 策略
- [ ] **无全局可写目录** — 检查文档根目录权限

```bash
# 检查并修复权限
chmod 640 /etc/nginx/nginx.conf
chmod 750 /etc/nginx/conf.d
chmod 600 /etc/nginx/ssl/*.key
chown -R root:root /etc/nginx
chown -R www-data:www-data /var/log/nginx
```

---

## 验证和测试

- [ ] **配置语法测试** — 每次更改后运行 `nginx -t`
- [ ] **使用 Gixy 安全扫描** — 运行 `gixy /etc/nginx/nginx.conf`
- [ ] **SSL Labs 测试** — 在 [ssllabs.com/ssltest](https://www.ssllabs.com/ssltest/) 获得 A 或 A+ 评分
- [ ] **安全头测试** — 在 [securityheaders.com](https://securityheaders.com/) 检查
- [ ] **Mozilla Observatory** — 在 [observatory.mozilla.org](https://observatory.mozilla.org/) 检查

---

## 快速验证命令

```bash
# 测试配置语法
nginx -t

# 使用 Gixy 安全扫描
gixy /etc/nginx/nginx.conf

# 检查完整配置转储
nginx -T

# 测试特定配置文件
nginx -t -c /path/to/nginx.conf

# 更改后重新加载
nginx -s reload
```

---

## 下载此检查清单

打印此页面或另存为 PDF 以供离线使用。对于自动化检查，使用 Gixy：

```bash
pip install gixy-ng
gixy /etc/nginx/nginx.conf --format json > audit-results.json
```

请参阅 [CI/CD 集成指南](ci-cd-integration.md) 了解如何在您的流水线中进行自动化安全检查。

---

## 相关资源

- [NGINX 安全加固完整指南](nginx-hardening-guide.md) — 详细说明和配置
- [安全头指南](nginx-security-headers.md) — HTTP 安全头深入解析
- [Gixy 文档](index.md) — 完整的自动化安全检查列表
- [在线 NGINX 检查器](https://www.getpagespeed.com/check-nginx-config) — 粘贴您的配置进行即时分析

--8<-- "zh/snippets/nginx-extras-cta.md"
