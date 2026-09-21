---
title: "文件系统根目录暴露"
description: "检测将请求映射到文件系统根目录的 NGINX root 和 alias 指令。"
---

# 文件系统根目录暴露

_Gixy 检查 ID：`filesystem_root_exposure`_

NGINX 的 [`root`](https://nginx.org/en/docs/http/ngx_http_core_module.html#root)
和 [`alias`](https://nginx.org/en/docs/http/ngx_http_core_module.html#alias)
指令会把请求路径转换为文件系统路径。将任一指令设为 `/`，会把操作系统根目录
作为映射基础：

```nginx
location / {
    root /;
}

location /files/ {
    alias /;
}
```

根据周围的 `location` 和访问控制，请求可能访问原本不应公开的敏感系统文件。
Gixy 还会检测最终解析为 `/` 的常量路径，例如 `/srv/..` 和 `/./`。包含变量的路径
不会报告，因为无法通过静态分析确定其运行时值。

## 如何修复？

请改用专用且范围明确的文档目录：

```nginx
location / {
    root /var/www/example;
}

location /files/ {
    alias /srv/downloads/;
}
```

确认所选目录只包含允许公开访问的文件，并为私有位置保留明确的访问控制。

--8<-- "zh/snippets/nginx-extras-cta.md"
