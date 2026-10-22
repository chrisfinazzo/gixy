---
title: "状态页暴露"
description: "保护 stub_status 不被公开访问：务必使用 allow/deny 指令加以限制，防止信息泄露。"
---

# 状态页暴露

_Gixy Check ID: `status_page_exposed`_


`stub_status` 模块会暴露 NGINX 服务器的指标，包括活动连接数、已处理的请求数和连接状态。若没有适当的 IP 限制，任何人都可以访问这些信息，从而为攻击者的侦察提供帮助。

## 错误示例

```nginx
location /status {
    stub_status;
}
```

或者使用了 `allow` 但缺少 `deny all`：

```nginx
location /status {
    stub_status;
    allow 10.0.0.0/8;
}
```

--8<-- "zh/snippets/amplify-cta.md"

## 正确示例

```nginx
location = /nginx-status {
    stub_status on;
    allow 127.0.0.1;
    allow ::1;
    deny all;
}
```

务必将 `stub_status` 与针对受信任 IP 的显式 `allow` 指令搭配使用，并以 `deny all` 拒绝其他所有来源。
