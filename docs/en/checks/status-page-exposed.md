---
title: "Status Page Exposed"
description: "Protect stub_status from public access: always restrict it with allow/deny directives to prevent information disclosure."
---

# Status Page Exposed

_Gixy Check ID: `status_page_exposed`_


The `stub_status` module exposes NGINX server metrics including active connections, requests handled, and connection states. Without proper IP restrictions, this information is accessible to anyone and can aid attackers in reconnaissance.

## Bad Example

```nginx
location /status {
    stub_status;
}
```

Or with `allow` but missing `deny all`:

```nginx
location /status {
    stub_status;
    allow 10.0.0.0/8;
}
```

--8<-- "en/snippets/amplify-cta.md"

## Good Example

```nginx
location = /nginx-status {
    stub_status on;
    allow 127.0.0.1;
    allow ::1;
    deny all;
}
```

Always pair `stub_status` with explicit `allow` directives for trusted IPs and a `deny all` to block everyone else.
