---
title: "Variables in Non-Expanding Directives"
description: "Detect $variables in NGINX geo, split_clients, location, server_name, regex, auth_request and path values, where NGINX uses the text literally."
---

# Variables in Non-Expanding Directives

_Gixy Check ID: `non_expanding_variable`_

Many NGINX directives expand variables, so it is easy to assume they all do.
[`map`](https://nginx.org/en/docs/http/ngx_http_map_module.html#map) values can
contain variables. [`geo`](https://nginx.org/en/docs/http/ngx_http_geo_module.html)
and [`split_clients`](https://nginx.org/en/docs/http/ngx_http_split_clients_module.html)
values cannot: NGINX stores `$binary_remote_addr` as the literal 19-character
string `$binary_remote_addr`. `nginx -t` reports no warning.

## The shared rate-limit bucket

This configuration looks like a per-client rate limit with an allowlist:

```nginx
geo $limit_key {
    default   $binary_remote_addr;   # stored literally!
    127.0.0.1 "";
}
limit_req_zone $limit_key zone=dynamic:10m rate=5r/s;
```

Every client outside the allowlist gets the same key, `$binary_remote_addr`,
so they all share **one** bucket. One crawler burst exhausts the limit and
real visitors get `503` responses. Gixy reports this as HIGH and names the
`limit_req_zone` or `limit_conn_zone` directive that uses the key.

## Safer alternative

Let `geo` classify clients and let a chained `map` expand the variable. This is
the allowlisting pattern from the
[NGINX rate limiting guide](https://blog.nginx.org/blog/rate-limiting-nginx):

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

Use the same approach for `split_clients`: return a literal marker, then map it
to a variable value.

## Matches that are never expanded

`location`, `server_name`, `rewrite` and `if` patterns are compiled once, when
NGINX loads the configuration, so variables in them are never substituted.
Gixy reports these as MEDIUM:

```nginx
set $admin admin;

# Prefix location: only matches the literal URI "/$admin/"
location /$admin/ { deny all; }

# Regex: "$" is the end-of-string anchor, so "^/$admin/" can never match
# and the deny is silently skipped
location ~ ^/$admin/ { deny all; }

rewrite ^/$old/(.*)$ /new/$1 permanent;   # never fires
if ($uri ~ $blocked) { return 403; }      # regex is the text "$blocked"
server_name $tenant.example.com;          # matches Host "$tenant.example.com"
```

Write the value out, or move the comparison into a `map`:

```nginx
location ~ ^/admin/ { deny all; }

map $uri $blocked_uri {
    default         0;
    ~^/private      1;
}
```

A dollar sign escaped as `\$` or inside a character class such as `[$]` is
a literal character and is not reported. `server_name $hostname` is a
documented special name and is accepted.

## auth_request URI

`auth_request` sends its subrequest to the URI exactly as written. With
`auth_request /auth/$host;` the subrequest goes to `/auth/$host`. If any
location answers that URI with a 2xx status, every request is authorized, so
Gixy reports this as HIGH. Use a fixed URI and pass request data to the auth
location in headers:

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

## Unrendered environment placeholders

NGINX does not read environment variables in its configuration. A
`${UPPER_CASE}` name that no `set`, `map` or other directive defines is almost
always a template placeholder that was never rendered:

```nginx
# Copied from a Docker template without running envsubst
proxy_pass http://${BACKEND_HOST}:8080;
```

Gixy reports these as MEDIUM. Render the template with `envsubst` before NGINX
starts. The official Docker image does this for
`/etc/nginx/templates/*.template`.

## Paths that do not support variables

These directives take their path literally and create files or directories with
`$` in the name. Gixy reports them as LOW:

| Directive | Literal argument |
|-----------|------------------|
| `error_log` | file path |
| `client_body_temp_path`, `proxy_temp_path`, `fastcgi_temp_path`, `uwsgi_temp_path`, `scgi_temp_path` | directory |
| `proxy_cache_path`, `fastcgi_cache_path`, `uwsgi_cache_path`, `scgi_cache_path` | directory |

```nginx
# Creates a file literally named "$host.error.log"
error_log /var/log/nginx/$host.error.log;
```

`access_log` does support variables, so it is not reported. Variables are also
expanded in `map` values, `add_header`, `proxy_set_header`, `root`, `alias`,
`try_files`, `proxy_pass` and the `limit_req_zone` key.

--8<-- "en/snippets/amplify-cta.md"
