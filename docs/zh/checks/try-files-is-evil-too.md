---
title: "没有 open_file_cache 的 try_files"
description: "使用 try_files 时启用 open_file_cache 以减少 stat() 开销并保持高吞吐量。"
---

# 没有 open_file_cache 的 try_files

_Gixy 检查 ID：`try_files_is_evil_too`_


`try_files` 指令通常在 nginx 中用于在回退到其他选项之前检查文件是否存在。但是，如果没有 `open_file_cache`，每个请求都会触发多个 `stat()` 系统调用，这可能会显著影响性能。

## 为什么这很重要

对于每个请求，`try_files` 使用 `stat()` 系统调用执行文件存在性检查。没有缓存时：

- **高 I/O 开销**：每个请求导致多次磁盘操作
- **性能下降**：在负载下，这成为瓶颈
- **延迟增加**：特别是在网络文件系统上（NFS、分布式存储）

## 错误示例

```nginx
location / {
    try_files $uri $uri/ /index.php$is_args$args;
}
```

每个请求将在没有任何缓存的情况下执行 2-3 次 `stat()` 调用。

## 正确示例

```nginx
# 在 http 或 server 级别启用文件缓存
open_file_cache max=1000 inactive=20s;
open_file_cache_valid 30s;
open_file_cache_min_uses 2;
open_file_cache_errors on;

location / {
    try_files $uri $uri/ /index.php$is_args$args;
}
```

使用 `open_file_cache`，nginx 缓存文件元数据，大大减少 `stat()` 调用。

## 缓存配置选项

| 指令 | 描述 |
|-----------|-------------|
| `open_file_cache max=N inactive=T` | 缓存最多 N 个条目，不活动 T 后过期 |
| `open_file_cache_valid T` | 多久验证一次缓存条目 |
| `open_file_cache_min_uses N` | 缓存前的最小访问次数 |
| `open_file_cache_errors on` | 也缓存"文件未找到"错误 |

## 何时禁用此检查

如果您提供的动态内容文件经常更改，或者使用 RAM 磁盘，性能影响可能可以忽略不计。您可以在 gixy 配置中禁用此特定检查。

## 参考资料

- [nginx 文档：open_file_cache](https://nginx.org/en/docs/http/ngx_http_core_module.html#open_file_cache)
- [try_files is evil too](https://www.getpagespeed.com/server-setup/nginx-try_files-is-evil-too)

--8<-- "zh/snippets/amplify-cta.md"
