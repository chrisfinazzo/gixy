---
title: "NGINX CVEs"
description: "Report CVEs that affect a specific installed NGINX version and configuration."
---

# NGINX CVEs

_Gixy Check ID: `nginx_cves`_


## Overview

The `nginx_cves` check mirrors the NGINX Open Source security advisory
database. Pass `--nginx-version=1.29.8` so gixy knows which NGINX binary
will load the config; without it, the check stays silent (gixy is a static config
analyzer and has no view of the binary).

Pure binary-level CVEs are reported whenever the supplied version falls
in an affected range. CVEs tied to a module or configuration pattern are
reported only when both the version and trigger match. Those reports
attach to the offending directives so you can see where the exposure is
enabled.

## Usage

```
gixy --nginx-version=1.29.8 /etc/nginx/nginx.conf
```

If your binary is patched, the check
stays silent for any CVE that has been fixed in that release, even if
the config still contains the trigger pattern. Without `--nginx-version`,
the check is silent altogether — there is nothing safe to assert about
a version we don't know.

## Current database

The database covers every NGINX Open Source CVE listed on the
[official security advisory page](https://nginx.org/en/security_advisories.html),
including version-range corrections for fixed stable branches.

The July 2026 security release adds config-aware detection for:

- **CVE-2026-42533:** regex `map` capture ordering and volatile map outputs.
- **CVE-2026-60005:** unnamed regex captures with `slice` or background
  cache updates.
- **CVE-2026-56434:** SSI processing of unbuffered proxied responses.

All three are fixed in NGINX Open Source `1.30.4` and `1.31.3`.

## Examples

### Config-triggered CVE

```
location ~(.*) {
    slice 1m;
    proxy_set_header X-Capture $1;
    proxy_set_header Range $slice_range;
    proxy_pass http://backend;
}
```

```
$ gixy --nginx-version=1.31.2 nginx.conf
==>>> Issue: [MEDIUM] Known nginx CVE affects your installed version.
CVE-2026-60005: Uninitialized memory access in ngx_http_slice_module.
Your installed version is vulnerable and the trigger pattern is present
in this config. Fixed in: 1.30.4, 1.31.3.
```

### Patched binary

```
$ gixy --nginx-version=1.30.4 nginx.conf  # silent: fix is present
```

## Extending the database

Append a dict to `CVES` in `gixy/plugins/_nginx_cves_db.py`:

```python
{
    "id": "CVE-YYYY-NNNNN",
    "nickname": "Optional Nickname",
    "summary": "One-line issue description.",
    "severity": gixy.severity.HIGH,
    "advisory": "https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN",
    "vulnerable_oss": (((LOW_MAJOR, LOW_MINOR, LOW_PATCH),
                        (HIGH_MAJOR, HIGH_MINOR, HIGH_PATCH)),),
    "fixed_oss": ("X.Y.Z", "A.B.C"),
    "fixed_plus": ("R<N> P<M>",),
    "config_check": check_cve_YYYY_NNNNN,  # or None for binary-only CVEs
}
```

If the CVE has a config-trigger pattern, add a small generator
function `check_cve_YYYY_NNNNN(root)` next to it that yields
`(primary_directive, related_directive)` pairs for each match.

## Limitations

- **OSS version matching.** The R-track patch model for NGINX Plus needs a
  per-track comparator; messages still mention Plus fix versions in
  plain text so Plus operators can apply them manually.
- **Direct sibling scope** for CVE-2026-42945's pattern check (matches
  the per-context script-engine compilation that produces the
  exploit). A `rewrite` inside an `if {}` block whose follow-up `set`
  lives outside that `if` is not flagged.
- **No auto-detection.** gixy does not shell out to `nginx -v`; you
  pass the version explicitly.
