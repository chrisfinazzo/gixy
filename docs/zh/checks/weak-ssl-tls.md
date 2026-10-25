---
title: "弱 SSL/TLS 配置"
description: "在 NGINX 中关闭旧版 TLS 和弱加密套件。迁移到现代 Mozilla 风格的套件以避免 POODLE/BEAST/Sweet32。"
---

# 弱 SSL/TLS 配置

_Gixy 检查 ID：`weak_ssl_tls`_


## 概述

`weak_ssl_tls` 插件检测可能危及加密连接安全性的不安全 SSL/TLS 配置。这包括过时的协议、弱加密套件和客户端驱动的加密选择。

## 检测内容

`ssl_ciphers` 按 OpenSSL 命令顺序分析：`!` 永久排除，`-` 可在之后重新加入，
开头的 `+` 只调整顺序，表达式内部的 `+` 表示交集。对于无法确定成员范围的
选择器，Gixy 会报告“可能选择了弱密码套件”；不会用本机 OpenSSL 的可用
套件来证明目标服务器安全。

### 1. 不安全的 TLS 协议
检测使用容易受到攻击的已弃用协议：

| 协议 | 状态 | 漏洞 |
|----------|--------|-----------------|
| SSLv2 | ❌ 不安全 | 多个严重缺陷 |
| SSLv3 | ❌ 不安全 | POODLE 攻击 |
| TLSv1.0 | ❌ 不安全 | BEAST、POODLE、CRIME |
| TLSv1.1 | ❌ 不安全 | 弱加密，无 AEAD |
| TLSv1.2 | ✅ 安全 | 配合强加密套件使用 |
| TLSv1.3 | ✅ 安全 | 现代，推荐 |

### 2. 弱加密套件
检测应该避免的加密套件：

- **NULL 加密** — 完全无加密
- **EXPORT 加密** — 故意削弱（40-56 位）
- **DES/3DES** — 易受 Sweet32 攻击
- **RC4** — 已破解的流加密
- **匿名加密 (ADH/AECDH)** — 无认证
- **基于 MD5 的加密** — 弱哈希函数

### 3. 服务器加密偏好
检测 `ssl_prefer_server_ciphers` 被禁用，允许客户端选择潜在更弱的加密。

## 示例

### ❌ 错误：启用了不安全的协议
```nginx
server {
    listen 443 ssl;
    ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;  # SSLv3、TLSv1、TLSv1.1 不安全
}
```
**问题**：`启用了不安全的协议：SSLv3、TLSv1、TLSv1.1`

### ❌ 错误：弱加密套件
```nginx
server {
    listen 443 ssl;
    ssl_ciphers ALL:RC4:DES:3DES;  # 包含弱加密
}
```
**问题**：`发现弱加密：RC4、DES、3DES`

### ✅ 正确：安全配置
```nginx
server {
    listen 443 ssl;

    # 仅现代协议
    ssl_protocols TLSv1.2 TLSv1.3;

    # Mozilla 中级加密套件
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    # 服务器选择加密
    ssl_prefer_server_ciphers on;

    # HSTS 由专用的 `hsts_header` 插件检查。
}
```

## 推荐配置

基于 [Mozilla SSL 配置生成器](https://ssl-config.mozilla.org/)：

### 中级配置（推荐）
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
```

### 现代配置（仅 TLSv1.3）
```nginx
ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers off;
```

## 为什么这很重要

弱 SSL/TLS 配置使您的服务器面临：

1. **POODLE 攻击**（SSLv3）— 允许解密安全连接
2. **BEAST 攻击**（TLSv1.0）— 允许解密 HTTPS cookie
3. **Sweet32 攻击**（3DES）— 允许从长连接恢复明文
4. **RC4 偏差** — 允许从加密流恢复明文
5. **降级攻击** — 强制使用更弱的协议

## 测试您的配置

使用这些工具验证您的 SSL/TLS 配置：

- [SSL Labs 服务器测试](https://www.ssllabs.com/ssltest/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- `openssl s_client -connect yoursite.com:443`

## 参考资料

- [Mozilla SSL 配置生成器](https://ssl-config.mozilla.org/)
- [Mozilla 服务器端 TLS 指南](https://wiki.mozilla.org/Security/Server_Side_TLS)
- [OWASP TLS 速查表](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)

--8<-- "zh/snippets/nginx-extras-cta.md"
