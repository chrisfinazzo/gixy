---
title: "Filesystem Root Exposure"
description: "Detect NGINX root and alias directives that map requests to the filesystem root."
---

# Filesystem Root Exposure

_Gixy Check ID: `filesystem_root_exposure`_

The NGINX [`root`](https://nginx.org/en/docs/http/ngx_http_core_module.html#root)
and [`alias`](https://nginx.org/en/docs/http/ngx_http_core_module.html#alias)
directives translate request paths into filesystem paths. Pointing either directive
at `/` makes the operating system's root directory the mapping base:

```nginx
location / {
    root /;
}

location /files/ {
    alias /;
}
```

Depending on the surrounding locations and access controls, requests may reach
sensitive system files that were never intended to be served. Gixy also detects
constant paths that resolve to `/`, such as `/srv/..` and `/./`. Paths containing
variables are not reported because their runtime value cannot be proven statically.

## What can I do?

Use a dedicated, narrowly scoped document directory instead:

```nginx
location / {
    root /var/www/example;
}

location /files/ {
    alias /srv/downloads/;
}
```

Confirm that the selected directory contains only files intended for public access,
and retain explicit access controls for private locations.

--8<-- "en/snippets/nginx-extras-cta.md"
