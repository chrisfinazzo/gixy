---
title: "NGINX CVEs"
description: "Report CVEs that affect a specific installed NGINX version and configuration."
---

# NGINX CVEs

_Gixy Check ID: `nginx_cves`_


## Overview

The `nginx_cves` check mirrors the NGINX Open Source security advisory
database. Pass `--nginx-version=1.31.6` so gixy knows which NGINX binary
will load the config; without it, the check stays silent (gixy is a static config
analyzer and has no view of the binary).

Pure binary-level CVEs are reported whenever the supplied version falls
in an affected range. CVEs tied to a module or configuration pattern are
reported only when both the version and trigger match. Those reports
attach to the offending directives so you can see where the exposure is
enabled.

## Usage

```
gixy --nginx-version=1.31.6 /etc/nginx/nginx.conf
```

If your binary is patched, the check
stays silent for any CVE that has been fixed in that release, even if
the config still contains the trigger pattern. Without `--nginx-version`,
the check is silent altogether — there is nothing safe to assert about
a version we don't know.

## Current database

As of October 2026, the database contains 63 of the 67 CVE IDs on the
[official NGINX Open Source security advisory page](https://nginx.org/en/security_advisories.html),
including fixed stable-branch version corrections. Four entries are intentionally
excluded: Windows-only CVE-2011-4963, CVE-2010-2266 and CVE-2010-2263, and
CVE-2009-4487 (log escaping, severity none, all versions, no fixed release).
These exclusions do not imply complete coverage of every NGINX-related product.

The September 2026 update includes CVE-2026-90439 in the HTTP/3 module,
fixed in Open Source `1.30.5` and `1.31.6`. The October release adds:

| CVE | Configuration prerequisites checked |
| --- | --- |
| [CVE-2026-15176](https://www.cve.org/CVERecord?id=CVE-2026-15176) | Effective `alias`, same/enclosing `rewrite`, and direct `$request_filename` or `${request_filename}` in applicable `set`/`return` expressions or an active access log's named `log_format`. |
| [CVE-2026-93479](https://www.cve.org/CVERecord?id=CVE-2026-93479) | Version-only advice; alternate non-cacheable-variable paths cannot be fully modeled from configuration. |
| [CVE-2026-95101](https://www.cve.org/CVERecord?id=CVE-2026-95101) | A QUIC listener with effective HTTP/3 enabled and `proxy_pass` with effective `proxy_request_buffering on` in the same HTTP server. |
| [CVE-2026-97629](https://www.cve.org/CVERecord?id=CVE-2026-97629) | A TLS HTTP server with effective `ssl_session_cache shared:...`, session tickets enabled and no explicit `ssl_session_ticket_key` files, allowing automatic ticket-key rotation. |
| [CVE-2026-97205](https://www.cve.org/CVERecord?id=CVE-2026-97205) | Effective `ssi on` and enabled AIO in the same applicable request context. |

All five October entries are fixed in NGINX Open Source `1.30.6` and `1.31.7`.
The trigger prerequisites follow the
[F5 CNA records](https://github.com/CVEProject/cvelistV5/tree/main/cves/2026);
historical OSS version bounds follow nginx.org, including `1.23.2` for
CVE-2026-97629. HTTP/server/location inheritance and nearer overrides are
considered without combining unrelated servers or sibling locations.

The July entries remain covered: CVE-2026-42533 (regex `map` captures and
volatile outputs), CVE-2026-60005 (unnamed captures with `slice` or background
cache updates), and CVE-2026-56434 (SSI with unbuffered proxied responses),
fixed in `1.30.4` and `1.31.3`.

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
$ gixy --nginx-version=1.30.6 nginx.conf  # silent: current fixes are present
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
- **Prerequisites are not exploit proof.** CVE-2026-97205 also requires SSI
  page contents containing `include virtual` commands; gixy does not inspect
  those files. CVE-2026-93479 remains a version-based advisory, not proof of
  an exploitable configuration.
- **Direct filename references.** CVE-2026-15176 checks lexical variable
  references and active named log formats; arbitrary variable indirection
  and request-time control flow are not fully modeled.
- **No auto-detection.** gixy does not shell out to `nginx -v`; you
  pass the version explicitly.
