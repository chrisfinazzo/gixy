---
title: "多行响应头"
description: "说明多行响应头已被标准弃用，可能导致代理或客户端解析异常，甚至触发安全问题。文章建议改用单行值与变量拼接，并给出兼容的 add_header 写法。适用于安全审计与上线前自检，帮助团队统一配置规范、减少误配并降低风险。"
---

# 多行响应头

_Gixy Check ID: `add_header_multiline`_


应避免使用多行响应头，因为：
- 它已被弃用（见 [RFC 7230](https://tools.ietf.org/html/rfc7230#section-3.2.4)）；
- 某些 HTTP 客户端和浏览器从未支持（例如 IE/Edge/Nginx）。

## 如何发现？
错误配置示例：
```nginx
# https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header
add_header Content-Security-Policy "
    default-src: 'none';
    script-src data: https://yastatic.net;
    style-src data: https://yastatic.net;
    img-src data: https://yastatic.net;
    font-src data: https://yastatic.net;";

# https://nginx-extras.getpagespeed.com/modules/headers-more/
more_set_headers -t 'text/html text/plain'
    'X-Foo: Bar
        multiline';
```

## 如何规避？
唯一的解决方案就是不要使用多行响应头。

--8<-- "zh/snippets/amplify-cta.md"
