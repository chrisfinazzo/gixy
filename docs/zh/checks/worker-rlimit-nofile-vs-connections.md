---
title: "worker_rlimit_nofile 与 worker_connections"
description: "将 worker_rlimit_nofile 提高到至少 worker_connections 的 2 倍，这样 NGINX 在负载下不会耗尽文件描述符。"
---

# 文件描述符限制

_Gixy 检查 ID：`worker_rlimit_nofile_vs_connections`_


一个常见的配置错误是没有将文件描述符（FD）限制提高到至少 `worker_connections` 值的两倍。要解决此问题，在主配置上下文中配置 `worker_rlimit_nofile` 指令，并确保它至少是 `worker_connections` 的两倍。

为什么需要额外的文件描述符？

* **Web 服务器模式**：
    * 客户端连接使用一个 FD。
    * 每个服务的文件需要额外的 FD，这意味着每个客户端至少需要两个 FD——如果网页由多个文件组成则更多。
* **代理服务器模式**：
    * 一个 FD 用于与客户端的连接。
    * 一个 FD 用于与上游服务器的连接。
    * 可能需要第三个 FD 用于临时存储上游服务器的响应。
* **缓存服务器模式**：
    * NGINX 在提供缓存响应时表现得像 Web 服务器（FD 使用方式类似）。
    * 当缓存为空或缓存内容过期时，它表现得像代理服务器。

通过确保 FD 限制至少是 `worker_connections` 数量的两倍，您可以满足这些不同操作模式的最低 FD 要求。

--8<-- "zh/snippets/amplify-cta.md"
