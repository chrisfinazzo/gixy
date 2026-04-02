---
title: "NGINX 安全头配置指南"
description: "NGINX 中 HTTP 安全头的完整配置指南：HSTS、CSP、X-Frame-Options、CORS 等。包含可复制粘贴的示例。"
keywords: "nginx 安全头, nginx HSTS, nginx Content-Security-Policy, nginx X-Frame-Options, nginx CORS 头, nginx add_header"
---

# NGINX 安全头配置

HTTP 安全头是防御 XSS、点击劫持和数据注入等客户端攻击的第一道防线。本指南涵盖了您应该在 NGINX 中配置的每个安全头。

!!! warning "关键：NGINX 中的头部继承"
    当您在子块（如 `location`）中使用 `add_header` 时，它会**完全覆盖**父块的所有头部。这是安全头配置错误的第一大原因。Gixy 可以[自动检测此问题](checks/add-header-redefinition.md)。

---

## 快速入门：必要的头部

将此块复制到您的服务器配置中以获得即时保护：

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name example.com;

    # === 必要的安全头 ===

    # HSTS - 强制 HTTPS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # 防止点击劫持
    add_header X-Frame-Options "SAMEORIGIN" always;

    # 防止 MIME 类型嗅探
    add_header X-Content-Type-Options "nosniff" always;

    # XSS 过滤器（旧版浏览器）
    add_header X-XSS-Protection "1; mode=block" always;

    # 控制 referrer 信息
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # 内容安全策略（根据您的应用自定义）
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; frame-ancestors 'self';" always;

    # 限制浏览器功能
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;

    # ... 您的其余配置
}
```

---

## 头部参考

### 1. Strict-Transport-Security (HSTS)

强制浏览器对您的域的所有未来请求使用 HTTPS。

**防御的攻击：** SSL 剥离、协议降级攻击

```nginx
# 基本 - 1 年
add_header Strict-Transport-Security "max-age=31536000" always;

# 包含子域
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# 准备好加入预加载列表
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

| 指令 | 描述 |
|-----------|-------------|
| `max-age` | 浏览器记住使用 HTTPS 的时间（秒） |
| `includeSubDomains` | 应用于所有子域 |
| `preload` | 有资格加入浏览器预加载列表 |

!!! danger "使用 `includeSubDomains` 之前"
    确保所有子域都有有效的 HTTPS。损坏的子域将完全无法访问。

!!! tip "推出策略"
    1. 从 `max-age=300`（5 分钟）开始
    2. 增加到 `max-age=86400`（1 天）
    3. 增加到 `max-age=604800`（1 周）
    4. 最后设置 `max-age=31536000`（1 年）

:white_check_mark: **Gixy 检查：** [`hsts_header`](checks/hsts-header.md)

---

### 2. Content-Security-Policy (CSP)

控制浏览器可以加载哪些资源。最强大的安全头。

**防御的攻击：** XSS、数据注入、点击劫持

```nginx
# 严格 CSP（会破坏大多数网站 - 从新项目开始）
add_header Content-Security-Policy "default-src 'self'" always;

# 典型 Web 应用
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://api.example.com; frame-ancestors 'self';" always;

# 仅报告模式（用于测试）
add_header Content-Security-Policy-Report-Only "default-src 'self'; report-uri /csp-report" always;
```

**常用指令：**

| 指令 | 控制内容 | 示例 |
|-----------|----------|---------|
| `default-src` | 其他指令的回退 | `'self'` |
| `script-src` | JavaScript 来源 | `'self' https://cdn.com` |
| `style-src` | CSS 来源 | `'self' 'unsafe-inline'` |
| `img-src` | 图片来源 | `'self' data: https:` |
| `font-src` | 字体来源 | `'self' https://fonts.gstatic.com` |
| `connect-src` | XHR、WebSocket、fetch | `'self' https://api.example.com` |
| `frame-src` | iframe 来源 | `'self'` |
| `frame-ancestors` | 谁可以嵌入此页面 | `'self'` |
| `base-uri` | 基础 URL 限制 | `'self'` |
| `form-action` | 表单提交目标 | `'self'` |

**来源值：**

| 值 | 含义 |
|-------|---------|
| `'self'` | 同源 |
| `'none'` | 全部阻止 |
| `'unsafe-inline'` | 允许内联脚本/样式（尽量避免） |
| `'unsafe-eval'` | 允许 eval()（避免） |
| `https:` | 任何 HTTPS URL |
| `data:` | Data URI |
| `'nonce-{random}'` | 带有匹配 nonce 的特定内联脚本 |
| `'sha256-{hash}'` | 带有匹配哈希的特定内联脚本 |

!!! tip "CSP 开发工作流程"
    1. 从 `Content-Security-Policy-Report-Only` 开始
    2. 监控报告以识别所需的来源
    3. 逐步收紧策略
    4. 切换到强制执行的 `Content-Security-Policy`

---

### 3. X-Frame-Options

防止您的页面被嵌入 iframe（点击劫持保护）。

**防御的攻击：** 点击劫持、UI 重定向

```nginx
# 拒绝所有框架
add_header X-Frame-Options "DENY" always;

# 仅允许同源
add_header X-Frame-Options "SAMEORIGIN" always;

# 允许特定来源（已弃用，改用 CSP frame-ancestors）
add_header X-Frame-Options "ALLOW-FROM https://trusted.com" always;
```

| 值 | 描述 |
|-------|-------------|
| `DENY` | 不能被任何人框架 |
| `SAMEORIGIN` | 只能被同源框架 |
| `ALLOW-FROM uri` | 已弃用，改用 CSP |

!!! note "现代替代方案"
    CSP 的 `frame-ancestors` 指令更灵活且广泛支持：
    ```nginx
    add_header Content-Security-Policy "frame-ancestors 'self' https://trusted.com" always;
    ```

---

### 4. X-Content-Type-Options

防止 MIME 类型嗅探攻击。

**防御的攻击：** MIME 混淆攻击、驱动下载

```nginx
add_header X-Content-Type-Options "nosniff" always;
```

只有一个有效值：`nosniff`。始终使用它。

---

### 5. X-XSS-Protection

启用浏览器内置的 XSS 过滤器。主要用于旧版浏览器。

**防御的攻击：** 反射型 XSS（在旧版浏览器中）

```nginx
add_header X-XSS-Protection "1; mode=block" always;
```

| 值 | 描述 |
|-------|-------------|
| `0` | 禁用过滤器 |
| `1` | 启用过滤器（净化） |
| `1; mode=block` | 启用过滤器（阻止页面） |

!!! note "现代浏览器"
    现代浏览器已弃用此头部，转而使用 CSP。但对 IE11 和旧版浏览器支持仍然有用。

---

### 6. Referrer-Policy

控制请求发送多少 referrer 信息。

**防御的攻击：** 信息泄露、隐私违规

```nginx
# 推荐用于大多数网站
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# 最大隐私
add_header Referrer-Policy "no-referrer" always;

# 仅同源
add_header Referrer-Policy "same-origin" always;
```

| 值 | 同源 | 跨源 (HTTPS→HTTPS) | 跨源 (HTTPS→HTTP) |
|-------|-------------|---------------------------|---------------------------|
| `no-referrer` | 无 | 无 | 无 |
| `same-origin` | 完整 URL | 无 | 无 |
| `strict-origin` | 仅来源 | 仅来源 | 无 |
| `strict-origin-when-cross-origin` | 完整 URL | 仅来源 | 无 |
| `origin-when-cross-origin` | 完整 URL | 仅来源 | 仅来源 |

---

### 7. Permissions-Policy（前身为 Feature-Policy）

限制对浏览器功能和 API 的访问。

**防御的攻击：** 不需要的功能访问、隐私违规

```nginx
# 禁用所有敏感功能
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()" always;

# 允许同源的特定功能
add_header Permissions-Policy "geolocation=(self), camera=(self), microphone=()" always;

# 允许特定来源的功能
add_header Permissions-Policy "geolocation=(self https://maps.example.com)" always;
```

**常用功能：**

| 功能 | 描述 |
|---------|-------------|
| `geolocation` | GPS/位置访问 |
| `camera` | 摄像头访问 |
| `microphone` | 麦克风访问 |
| `payment` | Payment Request API |
| `usb` | USB 设备访问 |
| `fullscreen` | 全屏 API |
| `autoplay` | 媒体自动播放 |
| `display-capture` | 屏幕捕获 |

---

### 8. 跨源头部

控制跨源资源访问。

#### Cross-Origin-Embedder-Policy (COEP)

```nginx
# 所有资源都需要 CORS/CORP
add_header Cross-Origin-Embedder-Policy "require-corp" always;

# 无凭据模式
add_header Cross-Origin-Embedder-Policy "credentialless" always;
```

#### Cross-Origin-Opener-Policy (COOP)

```nginx
# 隔离浏览上下文
add_header Cross-Origin-Opener-Policy "same-origin" always;

# 允许弹出窗口但隔离
add_header Cross-Origin-Opener-Policy "same-origin-allow-popups" always;
```

#### Cross-Origin-Resource-Policy (CORP)

```nginx
# 只有同源可以加载此资源
add_header Cross-Origin-Resource-Policy "same-origin" always;

# 同站点可以加载
add_header Cross-Origin-Resource-Policy "same-site" always;

# 任何来源都可以加载
add_header Cross-Origin-Resource-Policy "cross-origin" always;
```

!!! info "何时需要这些"
    这些头部是 `SharedArrayBuffer` 和高精度计时器等功能所必需的。大多数网站不需要它们。

---

## CORS 配置

对于需要接受跨源请求的 API：

```nginx
# 简单 CORS - 允许所有来源（仅限公共 API）
location /api/ {
    add_header Access-Control-Allow-Origin "*" always;
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;

    if ($request_method = OPTIONS) {
        return 204;
    }
}

# 特定来源 CORS
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

!!! danger "永远不要将 `*` 与凭据一起使用"
    `Access-Control-Allow-Origin: *` 不能与 `Access-Control-Allow-Credentials: true` 一起使用。这是浏览器安全限制。

---

## 解决头部继承问题

### 问题

```nginx
server {
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    location /api {
        add_header Access-Control-Allow-Origin "*" always;
        # X-Frame-Options 和 X-Content-Type-Options 现在消失了！
    }
}
```

### 解决方案 1：使用 `include` 引入公共头部

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

### 解决方案 2：使用 `headers-more` 模块

```nginx
# 在 http 级别设置不会被覆盖的头部
more_set_headers "X-Frame-Options: SAMEORIGIN";
more_set_headers "X-Content-Type-Options: nosniff";
```

### 解决方案 3：使用 `map` 实现动态头部

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

:white_check_mark: **Gixy 检查：** Gixy 的 [`add_header_redefinition`](checks/add-header-redefinition.md) 会自动检测父块中定义的头部在子块中被意外清除的情况。

---

## 完整配置示例

```nginx
http {
    # === 全局安全头 ===
    # 应用于所有服务器，除非被覆盖

    # 注意：如果任何 location 使用 add_header，这些将被清除
    # 使用 include 模式以保持一致性

    server {
        listen 443 ssl;
        http2 on;
        server_name example.com;

        # SSL 配置
        ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;

        # 在每个上下文中包含安全头
        include /etc/nginx/snippets/security-headers.conf;

        root /var/www/example.com;
        index index.html;

        location / {
            include /etc/nginx/snippets/security-headers.conf;
            try_files $uri $uri/ =404;
        }

        location /api/ {
            include /etc/nginx/snippets/security-headers.conf;

            # API 特定头部
            add_header Access-Control-Allow-Origin "https://app.example.com" always;
            add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE" always;

            proxy_pass http://backend;
        }

        location /embed/ {
            include /etc/nginx/snippets/security-headers.conf;

            # 为嵌入端点覆盖框架策略
            add_header X-Frame-Options "" always;  # 清除默认值
            add_header Content-Security-Policy "frame-ancestors https://partner.com" always;
        }
    }
}
```

**`/etc/nginx/snippets/security-headers.conf`：**

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

---

## 测试您的头部

### 在线工具

- [SecurityHeaders.com](https://securityheaders.com/) — 全面的头部分析
- [Mozilla Observatory](https://observatory.mozilla.org/) — 安全评估
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/) — CSP 策略分析

### 命令行

```bash
# 检查所有响应头
curl -I https://example.com

# 检查特定头部
curl -s -I https://example.com | grep -i "strict-transport"

# 详细输出检查
curl -v https://example.com 2>&1 | grep -i "< "
```

### 浏览器开发工具

1. 打开开发工具 (F12)
2. 转到 Network 标签
3. 点击任何请求
4. 查看 Response Headers

---

## 常见错误

### 1. 忘记 `always`

```nginx
# 错误：仅在成功响应时添加
add_header X-Frame-Options "SAMEORIGIN";

# 正确：在所有响应（包括错误）时添加
add_header X-Frame-Options "SAMEORIGIN" always;
```

### 2. 在 API 上使用错误的 CSP

```nginx
# 错误：带有 'self' 的 CSP 会阻止 API 响应
location /api/ {
    add_header Content-Security-Policy "default-src 'self'" always;
}

# 正确：API 使用不同的或不使用 CSP
location /api/ {
    # API 通常不需要 CSP
}
```

### 3. 在 HTTP 上使用 HSTS

```nginx
# 错误：端口 80 上的 HSTS（无用且奇怪）
server {
    listen 80;
    add_header Strict-Transport-Security "max-age=31536000" always;
}

# 正确：HSTS 仅在 HTTPS 上
server {
    listen 443 ssl;
    add_header Strict-Transport-Security "max-age=31536000" always;
}
```

---

## 相关资源

- [NGINX 安全加固完整指南](nginx-hardening-guide.md)
- [NGINX 安全检查清单](nginx-security-checklist.md)
- [Mozilla Web 安全指南](https://infosec.mozilla.org/guidelines/web_security)
- [OWASP 安全头项目](https://owasp.org/www-project-secure-headers/)

--8<-- "zh/snippets/nginx-extras-cta.md"
