---
title: "Setting Content-Type via add_header"
description: "Avoid duplicate Content-Type in NGINX. Use default_type for sane defaults and pair add_header with hide_header only when intentional."
---

# Setting Content-Type via add_header

_Gixy Check ID: `add_header_content_type`_


## Bad example

```nginx
add_header Content-Type text/plain;
```
This may result in duplicate `Content-Type` headers if your backend sets it.

## Good example

```nginx
default_type text/plain;
```

## Exception

Using `add_header Content-Type` in combination with any `*_hide_header Content-Type` directive is safe and will not trigger this check:

```nginx
proxy_hide_header Content-Type;
add_header Content-Type "application/octet-stream";
```

This pattern is valid because `*_hide_header` (such as `proxy_hide_header`, `fastcgi_hide_header`, `uwsgi_hide_header`, `scgi_hide_header`, or `grpc_hide_header`) prevents the backend's `Content-Type` from being passed through, and `add_header` then sets a new one, avoiding duplicate headers.

--8<-- "en/snippets/amplify-cta.md"
