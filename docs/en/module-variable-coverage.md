---
title: "Module Variable Coverage"
description: "Supported NGINX module variables, their possible values, reviewed source versions, deferred support and contributor checks."
---

# Module variable coverage

> **Unreleased (main branch, next release):** This matrix describes the planned
> next release after 0.2.58. The existing Brotli support and layered variable
> definitions are already present in 0.2.58. No new release or package publication
> is implied.

Gixy recognizes the variables listed below and uses their possible values to
check security: some contain numbers, some contain fixed cache status strings,
and others may contain arbitrary text. These definitions work without installing
the modules. Recognizing a variable neither loads its module nor proves that the
module is available or that the value is safe.

Unrestricted values may contain any characters, including line breaks, arbitrary
bytes and the empty string. Gixy records this as `[\s\S]*`. Numeric patterns below
also allow an empty result where the variable may be absent. Character restrictions
may allow more values than the module actually returns; they do not validate the
complete runtime format. Configuration declarations take precedence over the
bundled/vendor/administrator/explicit catalog layers.

The source links identify the exact module versions or commits reviewed. The review
covers both variable registration and the functions that return their values,
including branches for missing values and defaults.

## Supported variables

| Module and reviewed source version | Names or declaration syntax | Where values come from and allowed characters | Missing/default behavior | Previous support and changes |
| --- | --- | --- | --- | --- |
| [Zstd 0.2.2](https://github.com/GetPageSpeed/zstd-nginx-module/blob/0.2.2/filter/ngx_http_zstd_filter_module.c) | `zstd_ratio` | Counter formatting `%ui.%03ui`, `[0-9.]*` | not_found when unavailable | Adds support for this exact variable name |
| [Brotli v0.1.4](https://github.com/GetPageSpeed/ngx_brotli/blob/v0.1.4/filter/ngx_http_brotli_filter_module.c) | `brotli_ratio` | Compression counter formatting, `[0-9.]*` | Absent when unavailable | Retains the existing definition for this exact name |
| [NGINX 1.30.2 gzip](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/http/modules/ngx_http_gzip_filter_module.c) | `gzip_ratio` | `%ui.%02ui`, `[0-9.]*` | not_found | Replaces the safety assumption with explicit character restrictions |
| [srcache v0.32](https://github.com/dvershinin/srcache-nginx-module/blob/v0.32/src/ngx_http_srcache_var.c) | `srcache_fetch_status`, `srcache_store_status`, `srcache_expire` | Fetch `BYPASS\|MISS\|HIT`; store `BYPASS\|STORE`; signed expiry `[-0-9]*` | Missing context gives BYPASS statuses; expiry can be absent | Adds support for three exact variable names |
| [Echo v0.65 value-returning functions](https://github.com/openresty/echo-nginx-module/blob/v0.65/src/ngx_http_echo_var.c), [request info](https://github.com/openresty/echo-nginx-module/blob/v0.65/src/ngx_http_echo_request_info.c) | `echo_timer_elapsed`, `echo_incr`, `echo_response_status` | Timer `[0-9.]*`; increment/status `[0-9]*` | Absent/empty allowed | Adds support for three exact variable names |
| [Echo v0.65](https://github.com/openresty/echo-nginx-module/tree/v0.65/src) | `echo_request_method`, `echo_client_request_method`, `echo_cacheable_request_uri`, `echo_request_uri`, `echo_request_body`, `echo_client_request_headers`, `echo_it` | Request data or iterator output may contain any characters; headers include line breaks | Missing request/body/iterator context can be empty or absent | Adds support for seven exact variable names |
| [VTS v0.2.7](https://github.com/vozlt/nginx-module-vts/blob/v0.2.7/src/ngx_http_vhost_traffic_status_variables.c) | Exact 18-name list below | Unsigned counters/times `[0-9]*` | Absent allowed; cache variables are registered only with `NGX_HTTP_CACHE` | Adds support for 18 exact names without asserting module availability |
| [NGINX GeoIP HTTP](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/http/modules/ngx_http_geoip_module.c), [stream](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/stream/ngx_stream_geoip_module.c) | Exact 16-name union below | Area/DMA codes `[-0-9]*`; all other database values allow any characters | Absent allowed | Replaces blanket trust of `geoip_` with definitions for the listed exact names |
| [NGINX SSL HTTP](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/http/modules/ngx_http_ssl_module.c), [stream](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/stream/ngx_stream_ssl_module.c), [preread](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/stream/ngx_stream_ssl_preread_module.c), [value-returning functions](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/event/ngx_event_openssl.c) | Exact 30-name union below | Hex session ID/fingerprint `[0-9a-f]*`; reused `[r.]*`; early data `[1]*`; remaining days `[0-9]*`; preread protocol `[A-Za-z0-9.]*`; other values allow any characters | Empty/absent depends on handshake/certificate state | Replaces blanket trust of `ssl_` with definitions for the listed exact names |
| [max-lt JWT v3.4.6](https://github.com/max-lt/nginx-jwt-module/tree/v3.4.6), [kjdev JWT 76e0be2](https://github.com/kjdev/nginx-auth-jwt/tree/76e0be21811332e3d49c81ec72900b38a9661732) | Prefixes `jwt_claim_`, `jwt_header_`; exact `jwt_headers`, `jwt_payload`, `jwt_claims`, `jwt_nowtime` | Claims/headers/payload allow any characters; nowtime `[0-9]*`. max-lt JSON encoding does not imply literal CRLF, but the supported JWT implementations do not share a restriction on punctuation | Claims/headers may be missing | Replaces blanket trust of `jwt_` with only the documented prefixes and exact names |
| [GeoIP2 3.4 HTTP](https://github.com/leev/ngx_http_geoip2_module/blob/cbaa35461c62a99d2577e6bae3273492502d8769/ngx_http_geoip2_module.c), [stream](https://github.com/leev/ngx_http_geoip2_module/blob/cbaa35461c62a99d2577e6bae3273492502d8769/ngx_stream_geoip2_module.c) | `geoip2 db { $alias [default=bytes] [source=$expression] lookup path; }` | The database value type selects the return function; UTF8/BYTES are copied unchanged, so aliases and paths cannot restrict their characters | Missing/unsupported lookup uses literal default or not_found; found empty bypasses default | Recognizes aliases declared in configuration, only in HTTP/stream main |
| [GeoIP2 3.4 metadata](https://github.com/leev/ngx_http_geoip2_module/blob/cbaa35461c62a99d2577e6bae3273492502d8769/ngx_http_geoip2_module.c#L315-L337) | Exact `$alias metadata build_epoch;`, `last_check;`, `last_change;` | Unsigned build epoch `[0-9]*`; signed time fields `[-0-9]*` | Unknown/malformed metadata allows any characters; does not reproduce upstream out-of-bounds quirks | Recognizes metadata declarations; the last duplicate determines possible values before other declarations are processed |
| [Lua v0.10.31 setby](https://github.com/openresty/lua-nginx-module/blob/v0.10.31/src/ngx_http_lua_setby.c) | `set_by_lua $alias code [args...]`; `set_by_lua_file $alias path [args...]`; `set_by_lua_block $alias { body }` | Returned bytes are copied unchanged, so any characters are possible | Errors/empty outputs not interpreted; never execute or read script files | Treats inline/file/block script output as unrestricted text; preserves declaration arguments and the uninterpreted script body |
| [NGINX Perl 1.30.2](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/http/modules/perl/ngx_http_perl_module.c) | `perl_set $alias handler;` | Script result may contain any characters | No execution or inferred return type | Replaces the safety assumption with unrestricted text linked to its script declaration |
| [njs 0.8.7](https://github.com/nginx/njs/tree/0.8.7/nginx) | `js_set $alias function [nocache];`, `js_var $alias [initial];` | Callback results and writable values may contain any characters; an initializer cannot permanently restrict them | Context: HTTP/server/location and stream/server | Recognizes both declarations without tracking arbitrary script-side changes |

VTS exact names:
`vts_request_counter`, `vts_in_bytes`, `vts_out_bytes`, `vts_1xx_counter`,
`vts_2xx_counter`, `vts_3xx_counter`, `vts_4xx_counter`, `vts_5xx_counter`,
`vts_request_time_counter`, `vts_request_time`, `vts_cache_miss_counter`,
`vts_cache_bypass_counter`, `vts_cache_expired_counter`, `vts_cache_stale_counter`,
`vts_cache_updating_counter`, `vts_cache_revalidated_counter`,
`vts_cache_hit_counter`, `vts_cache_scarce_counter`.

GeoIP exact names:
`geoip_area_code`, `geoip_dma_code`, `geoip_country_code`, `geoip_country_code3`,
`geoip_country_name`, `geoip_org`, `geoip_city_continent_code`,
`geoip_city_country_code`, `geoip_city_country_code3`, `geoip_city_country_name`,
`geoip_region`, `geoip_region_name`, `geoip_city`, `geoip_postal_code`,
`geoip_latitude`, `geoip_longitude`. Database types are never inferred from names.

SSL exact names:
`ssl_session_id`, `ssl_client_fingerprint`, `ssl_session_reused`, `ssl_early_data`,
`ssl_client_v_remain`, `ssl_preread_protocol`, `ssl_protocol`, `ssl_cipher`,
`ssl_ciphers`, `ssl_curve`, `ssl_curves`, `ssl_sigalg`, `ssl_server_name`,
`ssl_alpn_protocol`, `ssl_ech_status`, `ssl_ech_outer_server_name`,
`ssl_client_cert`, `ssl_client_raw_cert`, `ssl_client_escaped_cert`,
`ssl_client_s_dn`, `ssl_client_i_dn`, `ssl_client_s_dn_legacy`,
`ssl_client_i_dn_legacy`, `ssl_client_serial`, `ssl_client_verify`,
`ssl_client_v_start`, `ssl_client_v_end`, `ssl_client_sigalg`,
`ssl_preread_server_name`, `ssl_preread_alpn_protocols`.

Gixy deliberately allows any characters in `ssl_server_name`. The
[value-returning function copies raw OpenSSL SNI](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/event/ngx_event_openssl.c#L5757-L5784).
[HTTP validation can decline and continue the default handshake](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/http/ngx_http_request.c#L918-L1028),
while [OpenSSL 3.5.0 validates length/NUL, not CRLF](https://github.com/openssl/openssl/blob/636dfadc70ce26f2473870570bfd9ec352806b1d/ssl/statem/extensions_srvr.c#L105-L174).
Ordinary `return 200/4xx/... text` is response body data, so HTTP-splitting only
checks redirect statuses 301/302/303/307/308 and the supported one-argument
`http://`, `https://`, `$scheme` shorthand. See the
[return parser](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/http/modules/ngx_http_rewrite_module.c#L442-L509)
and [response Location handling](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/http/ngx_http_core_module.c#L1794-L1812).

## Declaration ordering and collisions

Gixy collects GeoIP2 aliases in HTTP/stream main after expanding external includes
and before processing other values in that scope. Local names are case-insensitive;
numeric captures and captures from separate map entries stay distinct. Catalog
lookup keeps its existing case behavior. If only GeoIP2 declares the same name
more than once, the last declaration in expanded source order wins. Every alias
retains its original declaration file and line. Nested GeoIP2 blocks and invalid
inner includes cannot contribute aliases.

If a main-scope map/geo/js_set/js_var/perl_set declaration uses the same destination
name as GeoIP2, Gixy allows any characters in that value and warns with all of its
declaration locations. This treatment applies only to those exact declarations
in the current audit; source keys and captures are unaffected. Local `set`
continues to override inherited values. HTTP/stream scopes and separate audits
remain isolated.

## Reviewed and deferred

| Module and reviewed source version | Evidence and disposition |
| --- | --- |
| [set-misc v0.33](https://github.com/openresty/set-misc-nginx-module/tree/v0.33) | Defer configurable destinations, decoders, binary output and configurable alphabets until their declarations and possible values are covered separately; no invented safe prefix |
| [Memc v0.20](https://github.com/openresty/memc-nginx-module/tree/v0.20) | Defer five writable input slots and `flags_as_http_time`; needs separate definitions for writable inputs and returned values |
| [Redis2 v0.15](https://github.com/openresty/redis2-nginx-module/tree/v0.15) | Reviewed registration source: no new module variables |
| [headers-more v0.40](https://github.com/openresty/headers-more-nginx-module/tree/v0.40), [production v0.33](https://github.com/openresty/headers-more-nginx-module/tree/v0.33) | Reviewed registration source: no new module variables |
| [ModSecurity-nginx v1.0.4](https://github.com/owasp-modsecurity/ModSecurity-nginx/tree/v1.0.4) | Reviewed registration source: no new module variables |
| [ngx-fancyindex v0.6.1](https://github.com/dvershinin/ngx-fancyindex/tree/v0.6.1) | Reviewed active production module registration source: no variables |
| [length-hiding-filter 1.1.1](https://github.com/nulab/nginx-length-hiding-filter-module/tree/1.1.1) | Reviewed active production module registration source: no variables |
| [ngx_dynamic_etag 0.2.3](https://github.com/dvershinin/ngx_dynamic_etag/tree/0.2.3) | Reviewed active production module registration source: no variables |
| [ngx_ssl_handshake_padding 1.0.0](https://github.com/GetPageSpeed/ngx_ssl_handshake_padding/tree/332966bd2f7e7bc63a3d72d8df7d2f7abec48ff3) | Reviewed local tag source at commit `332966bd2f7e7bc63a3d72d8df7d2f7abec48ff3`: no variable registrations |
| [ngx_immutable 0.0.7](https://github.com/GetPageSpeed/ngx_immutable/tree/6835dad555d48b9dfbcd829f51d351370c78e1b1) | Reviewed local tag source at commit `6835dad555d48b9dfbcd829f51d351370c78e1b1`: no variable registrations |

These decisions follow checks of variable registration and value-returning
functions at the linked source versions. They make no claim about runtime
popularity or whether a module is installed on an audited host.

## Contributor checklist

1. Record the exact source version for variable registration tables and every
   function that returns a variable value. Include HTTP/stream differences,
   build flags, byte copying, formatting and error/missing branches.
2. Separate fixed names from configurable destinations and writable inputs.
   Record output origin, default/empty/not_found behavior and scope. Never infer
   database types or script return values from names, examples or initializers.
3. Use existing literal/regex/trusted catalog representations and typed
   declarations. Prefer exact names; only use a prefix if all members share
   character restrictions enforced by the source. Values that may contain any
   characters use `[\s\S]*`, never an empty value that asserts safety.
4. Write regressions before the fix: allowed/disallowed characters, missing/default
   cases, unsupported names, real splitting/SSRF/resolver findings, catalog
   overrides, include/order/scope/collision/audit isolation and declaration locations.
5. Preserve Python 3.6, no mandatory runtime dependency, no regex/script execution,
   no database/module loading. Run the full L1 and actual Python 3.6 suites, hooks,
   deterministic generated cases and the targeted mutation runner.
6. In disposable Linux containers, run
   `GIXY_DISPOSABLE_CONTAINER=1 python scripts/verify_variable_layers_linux.py`
   against the installed package. Keep its Linux/root/container guard; never run
   its system-file fixtures on a workstation. Cover file/stdin/no-argument CLI,
   library/server and disabled policy. Record executed cases and skips.
7. Update this matrix, translated variable docs, focused project rules and
   Unreleased changelog. Release/publication remains a separate authorized step.
