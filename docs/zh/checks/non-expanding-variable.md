---
title: "不展开变量的指令中的变量"
description: "检测 NGINX geo、split_clients、location、server_name、正则、auth_request 和路径值中被按字面使用的 $变量。"
---

# 不展开变量的指令中的变量

_Gixy Check ID: `non_expanding_variable`_

许多 NGINX 指令会展开变量，因此很容易以为所有指令都会这样做。
[`map`](https://nginx.org/en/docs/http/ngx_http_map_module.html#map) 的值可以包含变量，
而 [`geo`](https://nginx.org/en/docs/http/ngx_http_geo_module.html) 和
[`split_clients`](https://nginx.org/en/docs/http/ngx_http_split_clients_module.html)
的值不能：NGINX 会把 `$binary_remote_addr` 保存为 19 个字符的字面字符串
`$binary_remote_addr`。`nginx -t` 不会给出任何警告。

## 共享的限速桶

下面的配置看起来像是带白名单的按客户端限速：

```nginx
geo $limit_key {
    default   $binary_remote_addr;   # 按字面保存！
    127.0.0.1 "";
}
limit_req_zone $limit_key zone=dynamic:10m rate=5r/s;
```

白名单之外的所有客户端都得到同一个键 `$binary_remote_addr`，因此共享**一个**桶。
一次爬虫突发就会耗尽限额，真实访客会收到 `503`。Gixy 将其报告为 HIGH，
并指出使用该键的 `limit_req_zone` 或 `limit_conn_zone` 指令。

## 更安全的写法

让 `geo` 只负责分类客户端，再由链式 `map` 展开变量。这是
[NGINX 限速指南](https://blog.nginx.org/blog/rate-limiting-nginx)中的白名单模式：

```nginx
geo $limit {
    default   1;
    127.0.0.1 0;
    10.0.0.0/8 0;
}

map $limit $limit_key {
    0 "";
    1 $binary_remote_addr;
}

limit_req_zone $limit_key zone=dynamic:10m rate=5r/s;
```

`split_clients` 也采用同样的方法：返回字面标记，再用 `map` 映射到变量值。

## 永远不会展开的匹配模式

`location`、`server_name`、`rewrite` 和 `if` 的模式在 NGINX 加载配置时只编译一次，
其中的变量不会被替换。Gixy 将其报告为 MEDIUM：

```nginx
set $admin admin;

# 前缀 location：只匹配字面 URI "/$admin/"
location /$admin/ { deny all; }

# 正则：“$” 是字符串结尾锚点，因此 "^/$admin/" 永远不会匹配，
# deny 会被悄悄跳过
location ~ ^/$admin/ { deny all; }

rewrite ^/$old/(.*)$ /new/$1 permanent;   # 永远不会触发
if ($uri ~ $blocked) { return 403; }      # 正则就是文本 "$blocked"
server_name $tenant.example.com;          # 只匹配 Host "$tenant.example.com"
```

请直接写出值，或把比较移到 `map` 中：

```nginx
location ~ ^/admin/ { deny all; }

map $uri $blocked_uri {
    default         0;
    ~^/private      1;
}
```

转义为 `\$` 或位于 `[$]` 这样的字符类中的美元符号是普通字符，不会被报告。
`server_name $hostname` 是文档中规定的特殊名称，可以使用。

## auth_request 的 URI

`auth_request` 会把子请求按原样发送到所写的 URI。使用
`auth_request /auth/$host;` 时，子请求会发往 `/auth/$host`。如果任何 location
对该 URI 返回 2xx，所有请求都会被放行，因此 Gixy 将其报告为 HIGH。
请使用固定 URI，并通过请求头把数据传给认证 location：

```nginx
location / {
    auth_request /auth;
}

location = /auth {
    internal;
    proxy_set_header X-Original-Host $host;
    proxy_pass http://auth-backend;
}
```

## 未渲染的环境变量占位符

NGINX 不会在配置中读取环境变量。没有被 `set`、`map` 或其他指令定义的
`${UPPER_CASE}` 名称几乎总是未被渲染的模板占位符：

```nginx
# 从 Docker 模板复制而来，但没有运行 envsubst
proxy_pass http://${BACKEND_HOST}:8080;
```

Gixy 将其报告为 MEDIUM。请在 NGINX 启动前用 `envsubst` 渲染模板。
官方 Docker 镜像会对 `/etc/nginx/templates/*.template` 执行这一步。

## 不支持变量的路径

以下指令按字面使用路径，会创建名称中带 `$` 的文件或目录。Gixy 将其报告为 LOW：

| 指令 | 按字面使用的参数 |
|------|------------------|
| `error_log` | 文件路径 |
| `client_body_temp_path`、`proxy_temp_path`、`fastcgi_temp_path`、`uwsgi_temp_path`、`scgi_temp_path` | 目录 |
| `proxy_cache_path`、`fastcgi_cache_path`、`uwsgi_cache_path`、`scgi_cache_path` | 目录 |

```nginx
# 会创建一个名为 "$host.error.log" 的文件
error_log /var/log/nginx/$host.error.log;
```

`access_log` 支持变量，因此不会被报告。`map` 值、`add_header`、`proxy_set_header`、
`root`、`alias`、`try_files`、`proxy_pass` 以及 `limit_req_zone` 的键同样会展开变量。

--8<-- "zh/snippets/amplify-cta.md"
