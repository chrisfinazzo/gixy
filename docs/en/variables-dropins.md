---
title: "Variables & Layered Drop-ins"
description: "Supported NGINX variables, their possible values, and layered definitions that guide security checks."
---

# Variables & Drop-ins

Gixy recognizes supported NGINX variables and uses definitions of their possible
values when checking for security issues. A variable may contain numbers, fixed
cache status strings, or arbitrary text. These differences determine which
security checks can report a problem.

For example, the third-party variable `$brotli_ratio` can contain digits and dots,
or be absent. Gixy records these character restrictions as `[0-9.]*`: they exclude
CR/LF and slash, while retaining dots for conservative SSRF checks. This follows the
[GetPageSpeed ngx_brotli v0.1.4 value-returning function](https://github.com/GetPageSpeed/ngx_brotli/blob/v0.1.4/filter/ngx_http_brotli_filter_module.c#L778-L816).
Recognizing a name does not prove that the target module is installed or loaded,
or that its output is safe. Unknown names still produce diagnostic messages;
Gixy does not treat every name starting with `brotli_` as supported or safe.

## Module declarations and bundled coverage

> **Gixy 0.2.59:** The module declarations and bundled definitions in this
> section are available in 0.2.59. The layered catalog behavior below was
> already available in 0.2.58.

Built-in definitions now cover compression ratios, srcache statuses and expiry,
Echo, VTS counters, the exact GeoIP and SSL names, and documented JWT claims/headers.
They describe possible characters without asserting that a module is available.
Database, certificate, JWT and script values may contain any characters, including
line breaks, so Gixy continues to check them for security issues. Unsupported names
such as `$ssl_typo`, `$geoip_typo` and `$jwt_type` remain unknown. See the [coverage matrix with reviewed source versions](module-variable-coverage.md).

GeoIP2 aliases come from declarations in HTTP-main or stream-main configuration:

```nginx
http {
    geoip2 /usr/share/GeoIP/country.mmdb {
        $country default=US source=$remote_addr country iso_code;
        $database_epoch metadata build_epoch;
    }
    server { proxy_set_header X-Country $country; }
}
```

`$country` may contain any characters, including line breaks, even with
`iso_code` or `default=US`: runtime database values need not be country codes,
and defaults are literal bytes, not expressions. Only exact `metadata build_epoch`,
`metadata last_check` and `metadata last_change` forms restrict values to the
characters used for decimal numbers. Data aliases include empty, missing and
default outcomes.
Gixy never opens the database or evaluates source expressions to infer types.

Local declared names are case-insensitive. The last GeoIP2 declaration in expanded
source order wins throughout its main scope, including consumers before it.
Outer includes retain normal policy controls; includes inside GeoIP2 are invalid
and skipped before any filesystem or dump expansion. HTTP and stream scopes and
separate audits stay isolated. Configuration declarations beat catalog drop-ins,
even with system policy disabled.

If a main-scope map, geo, njs or Perl declaration uses the same destination name,
Gixy treats that variable as allowing any characters and reports the conflicting
declaration locations. Rename those destinations to establish unambiguous ownership. Local `set` assignments keep their
ordinary inherited override behavior.

`set_by_lua`, `set_by_lua_file`, `set_by_lua_block`, `perl_set`, `js_set` and
`js_var` return values that Gixy treats as unrestricted text, including line breaks.
Each definition retains the script declaration that supplies its value. Script
bodies and files are never executed or inspected for return values. A writable `js_var` initializer cannot
permanently constrain its output. Configuration-defined dynamic proxy hosts need
a resolver unless Gixy proves a literal IP or upstream; a regular expression
that describes possible values is never interpreted as a hostname.


## Layers and precedence

Ordinary CLI scans, including no-argument and stdin scans, load these layers
from lowest to highest precedence:

1. Built-in variable definitions.
2. Vendor/module files in `/usr/share/gixy/vars.d`.
3. Administrator files in `/etc/gixy/vars.d`.
4. Explicit directories from `--vars-dirs`, in supplied order (later wins).

Each directory forms its own layer. Files ending in `.cfg` or `.conf` are read
in lexical filename order; the last valid definition of a key wins, including
duplicates within one file. Invalid entries retain any valid earlier or lower
definition and warn with the source file and line.

Lookup selects the highest layer containing any match, then an exact name,
then the longest matching prefix ending in `_`. Thus a higher-layer `http_`
can override a lower-layer `http_host`. Within one layer, `http_host` wins over
`http_`, and `http_special_` wins over `http_` for `$http_special_value`.
This deterministic specificity rule corrects the earlier insertion-order
ambiguity. Variables defined by the analyzed NGINX configuration retain their
existing precedence over the catalog.

## Controls and isolation

Use one or more explicit directories with the existing comma-separated scalar
syntax:

```sh
gixy --vars-dirs /etc/gixy/vars,~/.config/gixy/vars
```

```cfg
# gixy.cfg: scalar text, without square brackets
vars-dirs = /etc/gixy/vars, ~/.config/gixy/vars
load-default-vars = false
```

`--no-default-vars` selects bundled-only policy unless explicit directories are
also supplied. `--load-default-vars` enables system directories. Opposite flags
cannot be combined. The canonical config key is `load-default-vars`, and the
environment variable is `GIXY_LOAD_DEFAULT_VARS=true` or `false`. Precedence is
CLI > environment > config > mode default, preserving explicit false values.
`--write-config` preserves an explicit choice using the canonical boolean key.
Explicit directories always augment enabled system layers at higher precedence.
The old `/etc/gixy/vars` and `~/.config/gixy/vars` locations still work when
selected explicitly; they are not searched automatically.

Library `Config(load_default_vars=False)` and `--server` default to bundled-only
policy. Operators can enable discovery or pass `vars_dirs` at startup. Individual
server requests and uploaded NGINX text cannot change this policy or select
policy paths. Each audit gets a fresh catalog, shared with its child contexts;
one audit's custom variable definitions do not affect another. Other global
analyzer state remains, so this is not a general thread-safety guarantee.

## File format

Each non-empty, non-comment line defines `name value`; `name = value` and
`name: value` also work. Names are ASCII identifiers without `$`; a trailing
`_` declares a prefix. Integer capture variables are not catalog variables.

```cfg
# /etc/gixy/vars.d/local.cfg
foo_host "example.com"
foo_literal 'a.b[$http_host]'
foo_uri r'/[^\s]*',
legacy_uri /[^\s]*
operator_asserted_safe none
```

Ordinary quoted text is a literal, with no variable interpolation, Python
unescaping or evaluation. Raw-prefixed quoted text (`r'...'` or `r"..."`) is a
regex; legacy unquoted regexes remain supported. Regexes undergo static syntax
analysis and are never executed against strings. Trailing commas are tolerated.
`none`, `null` (case-insensitive), `''` and `""` are explicit trusted assertions
that a value is not user-controlled. Use them only when justified: they can
suppress security findings. A missing value, unmatched quote, malformed name or
invalid regex is rejected rather than becoming a safety assertion.

## Trust and packaging

Automatic system policy must have root ownership and no group/world write
permission on every ancestor directory, the policy directory, and each regular
definition file. Symlinks, including ancestor symlinks, are rejected. Loading
uses held no-follow descriptors on supported POSIX systems; unsupported safe
loading warns and skips the system policy. Missing optional directories are
normal and scans never create them.

Explicit paths are trusted operator choices, support `~`, and work for non-root
users. Missing, unreadable and malformed selected files produce warnings. No
working-directory or implicit user-directory discovery occurs.

Module RPMs can ship ordinary root-owned `0644` vendor data without requiring
Gixy; Gixy's library package and module packages co-own the vendor directories
as root-owned `0755`. Administrator overrides belong in `/etc/gixy/vars.d`.
Removing module metadata falls back to bundled knowledge. Policy affects only
analysis, never NGINX behavior or module activation.
