---
title: "QUIC BPF Reuseport"
description: "Check older nginx builds for the quic_bpf, reuseport and multiple-worker reload issue."
---

# QUIC BPF Reuseport

_Gixy Check ID: `quic_bpf_reuseport`_


## Overview

The `quic_bpf_reuseport` check detects a combination that may drop QUIC (HTTP/3) connections after `nginx -s reload` on older upstream builds:

1. `quic_bpf on;` in the main context
2. `reuseport` on a QUIC listen socket
3. `worker_processes` > 1 (or `auto`)

Upstream nginx [1.31.7 includes the fix](https://nginx.org/en/CHANGES). Pass `--nginx-version=1.31.7` or newer to suppress this check for that upstream version. When the version is absent, invalid, or older, Gixy retains a conditional warning. Use `--nginx-version=auto` (or `nginx-version = auto` in Gixy's config) to opt into one local `nginx -V` probe per invocation. This asserts that the local binary is the scan target; use an explicit version for offline/remote targets. Detection is disabled by default and rejected in `--server` mode.

Bundled flavor evidence also suppresses this check for `nginx-mod` 1.30.6 or newer, recognized by `nginx version: nginx-mod by GetPageSpeed.com/1.30.6`, or supplied explicitly with `--nginx-version=1.30.6 --nginx-flavor=nginx-mod`. This threshold follows the [complete backport](https://bitbucket.org/danila_vershinin/nginx-mod/commits/207c5029e82cebaabc73aa0d17f9f1da2eaeadb3), [binary-upgrade follow-up](https://bitbucket.org/danila_vershinin/nginx-mod/commits/efd4041e097e8d30931178d8ff1691ac64cd13a7) and [1.30.6 update](https://bitbucket.org/danila_vershinin/nginx-mod/commits/4278150). Some 1.30.5 builds contain the backport, but that banner alone cannot prove it, so the warning remains. Upstream 1.30.6 also retains the warning.

An unknown vendor uses upstream rules. `--nginx-flavor=upstream` explicitly overrides detected flavor. Detection failures warn on stderr and leave the version unknown; a failed `auto` never falls back to `nginx-cves-version`. Fix overrides apply only to their exact check/CVE key, without changing the advertised version or suppressing other findings. The detected identity is logged on stderr, and `--debug` shows applied overrides. See [target version configuration](../configuration.md#target-nginx-version-and-flavor).

For a detailed explanation, see the [GetPageSpeed article](https://www.getpagespeed.com/server-setup/nginx/nginx-http3-reload-quic-connections-fail).

## What it detects

Triggers when **all three** conditions are present simultaneously.

## Examples

### Bad: All three conditions present

```nginx
worker_processes auto;

quic_bpf on;
events {}

http {
    server {
        listen 443 quic reuseport;
        listen 443 ssl;
        server_name example.com;
    }
}
```

### Good: quic_bpf disabled

```nginx
worker_processes auto;

quic_bpf off;
events {}

http {
    server {
        listen 443 quic reuseport;
        listen 443 ssl;
        server_name example.com;
    }
}
```

### Good: Single worker (bug doesn't trigger)

```nginx
worker_processes 1;

quic_bpf on;
events {}

http {
    server {
        listen 443 quic reuseport;
        listen 443 ssl;
        server_name example.com;
    }
}
```

## Fix

Disable `quic_bpf` in the main context or use an nginx build that includes the upstream fix. `--nginx-version` is shared with the NGINX CVE check; the older `--nginx-cves-version` input remains a shared fallback when the global option is absent.
