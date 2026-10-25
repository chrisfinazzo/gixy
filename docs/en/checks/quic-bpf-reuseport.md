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

Upstream nginx [1.31.7 includes the fix](https://nginx.org/en/CHANGES). Pass `--nginx-version=1.31.7` or newer to suppress this check for that upstream version. When the version is absent, invalid, or older, Gixy retains a conditional warning. Vendor builds may contain a backport that the version number alone cannot establish. Gixy does not detect an installed binary automatically.

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
