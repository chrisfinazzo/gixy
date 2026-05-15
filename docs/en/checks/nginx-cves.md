---
title: "Nginx CVEs"
description: "Report CVEs that affect a specific installed nginx version, with config-pattern enrichment for triggerable bugs."
---

# Nginx CVEs

_Gixy Check ID: `nginx_cves`_


## Overview

The `nginx_cves` check maintains a small database of known nginx CVEs.
Pass `--nginx-version=1.29.8` so gixy knows which nginx binary will load
the config; without it, the check stays silent (gixy is a static config
analyzer and has no view of the binary).

Every CVE whose affected version range covers the supplied version is
reported with the upgrade target. For CVEs that also have a
config-trigger pattern, the report enriches with the offending
directives — so you can see both "your binary is vulnerable" and "your
config triggers it here" at once.

## Usage

```
gixy --nginx-version=1.29.8 /etc/nginx/nginx.conf
```

If your binary is patched (e.g. `--nginx-version=1.30.1`), the check
stays silent for any CVE that has been fixed in that release, even if
the config still contains the trigger pattern. Without `--nginx-version`,
the check is silent altogether — there is nothing safe to assert about
a version we don't know.

## Current database

### CVE-2026-42945 ("NGINX Rift")

- **Severity:** HIGH (CVSS 9.2)
- **Affected:** nginx OSS `0.6.27`..`1.30.0`; nginx Plus `R32`..`R36`
- **Fixed in:** `1.30.1`, `1.31.0`; Plus `R32 P6`, `R36 P4`
- **Trigger pattern:** a `rewrite` whose replacement contains both an
  unnamed PCRE backreference (`$1`..`$9` or `${1}`..`${9}`) and a
  literal `?`, followed by another `rewrite`, `if`, or `set` in the
  same parent context. The script engine compiles an under-sized
  destination buffer using one escaping method, then writes via
  `NGX_ESCAPE_ARGS` in a second pass — the difference overflows the
  heap.
- **Mitigation:** switch to named captures (`(?<name>...)` referenced
  as `${name}`), or upgrade.
- **Advisory:** [NVD CVE-2026-42945](https://nvd.nist.gov/vuln/detail/CVE-2026-42945)

## Examples

### Vulnerable binary, no trigger in config

```
$ gixy --nginx-version=1.29.8 nginx.conf
==>>> Issue: [HIGH] Known nginx CVE affects your installed version.
CVE-2026-42945 ("NGINX Rift"): Heap overflow in ngx_http_rewrite_module.
Your installed version falls in the affected range. Fixed in: 1.30.1,
1.31.0 (Plus: R32 P6, R36 P4). Advisory: https://nvd.nist.gov/...
```

### Vulnerable binary AND trigger pattern present

```
location / {
    rewrite ^/(.*)$ /x?$1 last;
    set $foo bar;
}
```

```
$ gixy --nginx-version=1.29.8 nginx.conf
==>>> Issue: [HIGH] Known nginx CVE affects your installed version.
CVE-2026-42945 ("NGINX Rift"): Heap overflow in ngx_http_rewrite_module.
Your installed version is vulnerable AND the trigger pattern is
present in this config. Fixed in: 1.30.1, 1.31.0 (Plus: R32 P6, R36 P4).
```

### Patched binary

```
$ gixy --nginx-version=1.30.1 nginx.conf  # silent — fix is in
```

## Extending the database

Append a dict to `_CVES` in `gixy/plugins/nginx_cves.py`:

```python
{
    "id": "CVE-YYYY-NNNNN",
    "nickname": "Optional Nickname",
    "summary": "One-line issue description.",
    "severity": gixy.severity.HIGH,
    "advisory": "https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN",
    "affected_oss": ((LOW_MAJOR, LOW_MINOR, LOW_PATCH),
                     (HIGH_MAJOR, HIGH_MINOR, HIGH_PATCH)),
    "fixed_oss": ("X.Y.Z", "A.B.C"),
    "fixed_plus": ("R<N> P<M>",),
    "config_check": _check_cve_YYYY_NNNNN,  # or None for binary-only CVEs
}
```

If the CVE has a config-trigger pattern, add a small generator
function `_check_cve_YYYY_NNNNN(root)` next to it that yields
`(primary_directive, related_directive)` pairs for each match.

## Limitations

- **OSS only in v1.** The R-track patch model for nginx Plus needs a
  per-track comparator; messages still mention Plus fix versions in
  plain text so Plus operators can apply them manually.
- **Direct sibling scope** for CVE-2026-42945's pattern check (matches
  the per-context script-engine compilation that produces the
  exploit). A `rewrite` inside an `if {}` block whose follow-up `set`
  lives outside that `if` is not flagged.
- **No auto-detection.** gixy does not shell out to `nginx -v`; you
  pass the version explicitly.
