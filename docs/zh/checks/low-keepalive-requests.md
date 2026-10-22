---
title: "低 keepalive_requests 值"
description: "非常低的 keepalive_requests 会导致过早关闭连接——对 HTTP/2 性能不利。建议使用 1000+ 或默认值。"
---

# 低 keepalive_requests 值

_Gixy 检查 ID：`low_keepalive_requests`_


`keepalive_requests` 指令设置通过一个 keep-alive 连接可以服务的最大请求数。在达到最大请求数后，连接将被关闭。

## 为什么这很重要

在 nginx 1.19.10 之前，默认值是 100。后来提高到 1000，因为低值可能会导致问题：

- **HTTP/2 多路复用**：现代浏览器打开较少的连接，但通过每个连接发送许多请求。低 `keepalive_requests` 值会导致频繁的连接重置。
- **客户端断开连接**：某些客户端（特别是通过 Burp 或 mitmproxy 等代理使用 HTTP/2 时）可能会在连接过早关闭时遇到请求失败。
- **性能开销**：建立新连接有开销（TCP 握手、TLS 协商）。保持连接活跃更长时间可以提高性能。

## 错误示例

```nginx
keepalive_requests 100;
```

这会在仅 100 个请求后强制关闭连接，可能会导致 HTTP/2 客户端出现问题。

## 正确示例

```nginx
keepalive_requests 1000;
```

或者简单地省略该指令以使用 nginx 的默认值（自 nginx 1.19.10 以来为 1000）。

## 参考资料

- [nginx 文档：keepalive_requests](https://nginx.org/en/docs/http/ngx_http_core_module.html#keepalive_requests)
- [nginx 工单 #2155：增加默认 keepalive_requests](https://trac.nginx.org/nginx/ticket/2155)

--8<-- "zh/snippets/amplify-cta.md"
