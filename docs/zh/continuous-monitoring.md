---
title: "使用 GetPageSpeed Amplify 持续监控"
description: "将 Gixy 与 GetPageSpeed Amplify 搭配使用，实现定时、持续的 Gixy 安全扫描以及完整的 NGINX 运行时监控。可直接替代已弃用的 nginx-amplify-agent。"
---

# 使用 GetPageSpeed Amplify 持续监控

一次性执行 `gixy /etc/nginx/nginx.conf` 很有用，但生产环境的配置会不断漂移：新增了 server 块，`proxy_pass` 被重构，`Header` 指令被悄悄放进了不安全的上下文。在每台主机上定时运行 Gixy，并把检测结果与 NGINX 运行时指标关联起来，才能在这些回归影响用户之前将其发现。

[**GetPageSpeed Amplify**](https://amplify.getpagespeed.com/) 正是为此而生。它是 F5 已弃用的 NGINX Amplify 监控服务的直接替代品，并内置了 Gixy。

## 能获得什么

- **定时 Gixy 扫描**：覆盖所有受监控的主机，检测结果集中展示在同一个仪表盘中并保留历史记录。
- **NGINX 运行时指标**（请求、上游、缓存、SSL、连接）与 Gixy 报告并排展示，安全问题会出现在它本可能影响到的流量旁边。
- **告警**：针对新出现的 Gixy 检测结果以及运行时异常发出告警。
- **直接兼容**现有的 `nginx-amplify-agent`。如果你在弃用之前使用的是 F5 的 NGINX Amplify，迁移只需修改 `api_url`。

## 安装

在每台 NGINX 主机上执行：

```sh
curl -sS https://amplify.getpagespeed.com/install | sudo bash
```

如果你要迁移现有的 `nginx-amplify-agent` 安装，请编辑 `/etc/amplify-agent/agent.conf`，将 `api_url` 指向 GetPageSpeed Amplify 的端点而不是已弃用的上游地址，然后执行 `sudo systemctl restart amplify-agent`。

在 <https://amplify.getpagespeed.com/> 注册并获取你的 API 令牌。

## 了解更多

包含截图和验证步骤的完整迁移指南见 [gixy.org/guides/nginx-monitoring-amplify](https://gixy.org/guides/nginx-monitoring-amplify)。
