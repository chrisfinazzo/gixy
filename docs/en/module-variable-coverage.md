---
title: "Module Variable Coverage"
description: "Source-pinned module getter models, declaration semantics, deferred candidates and contributor checks."
---

# Module variable coverage

> **Unreleased (main branch, next release):** This matrix describes the planned
> next release after 0.2.58. The retained Brotli and layered catalog models are
> already present in 0.2.58. No new release or package publication is implied.

These portable fallback models describe possible output characters, independently
of installed modules. They neither load modules nor prove availability. `opaque`
means `[\s\S]*`, including empty and arbitrary bytes; numeric patterns below
include empty for absent outcomes. Patterns are conservative character bounds,
not full runtime syntax validators. Configuration declarations override the
bundled/vendor/administrator/explicit catalog layers.

## Implemented models

| Module and source pin | Names or declaration syntax | Output origin and bounds | Missing/default behavior | Prior coverage and implemented route |
| --- | --- | --- | --- | --- |
| [Zstd 0.2.2](https://github.com/GetPageSpeed/zstd-nginx-module/blob/0.2.2/filter/ngx_http_zstd_filter_module.c) | `zstd_ratio` | Counter formatting `%ui.%03ui`, `[0-9.]*` | not_found when unavailable | Missing; exact bundled name |
| [Brotli v0.1.4](https://github.com/GetPageSpeed/ngx_brotli/blob/v0.1.4/filter/ngx_http_brotli_filter_module.c) | `brotli_ratio` | Compression counter formatting, `[0-9.]*` | Absent when unavailable | Retain existing exact model |
| [NGINX 1.30.2 gzip](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/http/modules/ngx_http_gzip_filter_module.c) | `gzip_ratio` | `%ui.%02ui`, `[0-9.]*` | not_found | Replace trusted exact name with bound |
| [srcache v0.32](https://github.com/dvershinin/srcache-nginx-module/blob/v0.32/src/ngx_http_srcache_var.c) | `srcache_fetch_status`, `srcache_store_status`, `srcache_expire` | Fetch `BYPASS\|MISS\|HIT`; store `BYPASS\|STORE`; signed expiry `[-0-9]*` | Missing context gives BYPASS statuses; expiry can be absent | Three missing exact bundled models |
| [Echo v0.65 getters](https://github.com/openresty/echo-nginx-module/blob/v0.65/src/ngx_http_echo_var.c), [request info](https://github.com/openresty/echo-nginx-module/blob/v0.65/src/ngx_http_echo_request_info.c) | `echo_timer_elapsed`, `echo_incr`, `echo_response_status` | Timer `[0-9.]*`; increment/status `[0-9]*` | Absent/empty allowed | Three missing exact bundled models |
| [Echo v0.65](https://github.com/openresty/echo-nginx-module/tree/v0.65/src) | `echo_request_method`, `echo_client_request_method`, `echo_cacheable_request_uri`, `echo_request_uri`, `echo_request_body`, `echo_client_request_headers`, `echo_it` | Request data or iterator output: opaque, headers include line breaks | Missing request/body/iterator context can be empty or absent | Seven missing exact bundled models |
| [VTS v0.2.7](https://github.com/vozlt/nginx-module-vts/blob/v0.2.7/src/ngx_http_vhost_traffic_status_variables.c) | Exact 18-name list below | Unsigned counters/times `[0-9]*` | Absent allowed; cache getter registration depends on `NGX_HTTP_CACHE` | 18 missing exact bundled models; no availability assertion |
| [NGINX GeoIP HTTP](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/http/modules/ngx_http_geoip_module.c), [stream](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/stream/ngx_stream_geoip_module.c) | Exact 16-name union below | Area/DMA codes `[-0-9]*`; all other database getters opaque | Absent allowed | Remove universal trusted `geoip_`; finite exact models |
| [NGINX SSL HTTP](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/http/modules/ngx_http_ssl_module.c), [stream](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/stream/ngx_stream_ssl_module.c), [preread](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/stream/ngx_stream_ssl_preread_module.c), [getters](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/event/ngx_event_openssl.c) | Exact 30-name union below | Hex session ID/fingerprint `[0-9a-f]*`; reused `[r.]*`; early data `[1]*`; remaining days `[0-9]*`; preread protocol `[A-Za-z0-9.]*`; others opaque | Empty/absent depends on handshake/certificate state | Remove universal trusted `ssl_`; finite exact models |
| [max-lt JWT v3.4.6](https://github.com/max-lt/nginx-jwt-module/tree/v3.4.6), [kjdev JWT 76e0be2](https://github.com/kjdev/nginx-auth-jwt/tree/76e0be21811332e3d49c81ec72900b38a9661732) | Prefixes `jwt_claim_`, `jwt_header_`; exact `jwt_headers`, `jwt_payload`, `jwt_claims`, `jwt_nowtime` | Claims/headers/payload opaque; nowtime `[0-9]*`. max-lt JSON encoding does not imply literal CRLF, but cross-provider punctuation remains unconstrained | Claims/headers may be missing | Remove universal trusted `jwt_`; only documented prefixes/exacts |
| [GeoIP2 3.4 HTTP](https://github.com/leev/ngx_http_geoip2_module/blob/cbaa35461c62a99d2577e6bae3273492502d8769/ngx_http_geoip2_module.c), [stream](https://github.com/leev/ngx_http_geoip2_module/blob/cbaa35461c62a99d2577e6bae3273492502d8769/ngx_stream_geoip2_module.c) | `geoip2 db { $alias [default=bytes] [source=$expression] lookup path; }` | Runtime database type selects getter; UTF8/BYTES copied unchanged, hence opaque regardless of alias/path | Missing/unsupported lookup uses literal default or not_found; found empty bypasses default | Missing; typed block declares arbitrary aliases only in HTTP/stream main |
| [GeoIP2 3.4 metadata](https://github.com/leev/ngx_http_geoip2_module/blob/cbaa35461c62a99d2577e6bae3273492502d8769/ngx_http_geoip2_module.c#L315-L337) | Exact `$alias metadata build_epoch;`, `last_check;`, `last_change;` | Unsigned build epoch `[0-9]*`; signed time fields `[-0-9]*` | Unknown/malformed metadata remains opaque; no emulation of upstream out-of-bounds quirks | New declaration models, final duplicate wins before sibling compilation |
| [Lua v0.10.31 setby](https://github.com/openresty/lua-nginx-module/blob/v0.10.31/src/ngx_http_lua_setby.c) | `set_by_lua $alias code [args...]`; `set_by_lua_file $alias path [args...]`; `set_by_lua_block $alias { body }` | Return bytes copied unchanged: opaque | Errors/empty outputs not interpreted; never execute or read script files | Correct trusted inline result; add file/block destinations and retain opaque raw body/header args |
| [NGINX Perl 1.30.2](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/http/modules/perl/ngx_http_perl_module.c) | `perl_set $alias handler;` | Script result opaque | No execution or inferred return type | Replace empty trusted placeholder with provider-owned opaque model |
| [njs 0.8.7](https://github.com/nginx/njs/tree/0.8.7/nginx) | `js_set $alias function [nocache];`, `js_var $alias [initial];` | Callback/writable result opaque; initializer is not a permanent bound | Context: HTTP/server/location and stream/server | New typed providers; no generic script mutation tracking |

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

The opaque `ssl_server_name` bound is deliberate. The
[getter copies raw OpenSSL SNI](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/event/ngx_event_openssl.c#L5757-L5784).
[HTTP validation can decline and continue the default handshake](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/http/ngx_http_request.c#L918-L1028),
while [OpenSSL 3.5.0 validates length/NUL, not CRLF](https://github.com/openssl/openssl/blob/636dfadc70ce26f2473870570bfd9ec352806b1d/ssl/statem/extensions_srvr.c#L105-L174).
Ordinary `return 200/4xx/... text` is response body data, so HTTP-splitting only
checks redirect statuses 301/302/303/307/308 and the supported one-argument
`http://`, `https://`, `$scheme` shorthand. See the
[return parser](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/http/modules/ngx_http_rewrite_module.c#L442-L509)
and [response Location handling](https://github.com/nginx/nginx/blob/a92a537860c7b87d3793d9eb41c9cf3ed833b53c/src/http/ngx_http_core_module.c#L1794-L1812).

## Declaration ordering and collisions

Main-scope GeoIP2 aliases are finalized after external includes expand and before
ordinary sibling values compile. Lowercase local keys preserve numeric capture
keys and map context discriminators; catalog lookup keeps its existing case
behavior. Final GeoIP2-only duplicates win in expanded source order. Children
are generic declarations with their original file/line provenance. Nested
GeoIP2 blocks and invalid inner includes cannot contribute aliases.

Only overlapping main-scope map/geo/js_set/js_var/perl_set destinations get an
opaque collision override with aggregate declaration provenance and an actionable
warning. Exact provider-node/name keys are owned by one audit. Source keys and
captures never collide through this table. Local `set` continues to override
inherited values. HTTP/stream and repeated audit state remain isolated.

## Reviewed and deferred

| Module/source pin | Evidence and disposition |
| --- | --- |
| [set-misc v0.33](https://github.com/openresty/set-misc-nginx-module/tree/v0.33) | Defer configurable destinations, decoders, binary output and configurable alphabets for separate declaration modeling; no invented safe prefix |
| [Memc v0.20](https://github.com/openresty/memc-nginx-module/tree/v0.20) | Defer five writable input slots and `flags_as_http_time`; needs separate writable/output modeling |
| [Redis2 v0.15](https://github.com/openresty/redis2-nginx-module/tree/v0.15) | Reviewed registration source: no new module variables |
| [headers-more v0.40](https://github.com/openresty/headers-more-nginx-module/tree/v0.40), [production v0.33](https://github.com/openresty/headers-more-nginx-module/tree/v0.33) | Reviewed registration source: no new module variables |
| [ModSecurity-nginx v1.0.4](https://github.com/owasp-modsecurity/ModSecurity-nginx/tree/v1.0.4) | Reviewed registration source: no new module variables |
| [ngx-fancyindex v0.6.1](https://github.com/dvershinin/ngx-fancyindex/tree/v0.6.1) | Reviewed active production module registration source: no variables |
| [length-hiding-filter 1.1.1](https://github.com/nulab/nginx-length-hiding-filter-module/tree/1.1.1) | Reviewed active production module registration source: no variables |
| [ngx_dynamic_etag 0.2.3](https://github.com/dvershinin/ngx_dynamic_etag/tree/0.2.3) | Reviewed active production module registration source: no variables |
| [ngx_ssl_handshake_padding 1.0.0](https://github.com/GetPageSpeed/ngx_ssl_handshake_padding/tree/332966bd2f7e7bc63a3d72d8df7d2f7abec48ff3) | Reviewed local tag source at commit `332966bd2f7e7bc63a3d72d8df7d2f7abec48ff3`: no variable registrations |
| [ngx_immutable 0.0.7](https://github.com/GetPageSpeed/ngx_immutable/tree/6835dad555d48b9dfbcd829f51d351370c78e1b1) | Reviewed local tag source at commit `6835dad555d48b9dfbcd829f51d351370c78e1b1`: no variable registrations |

These dispositions reflect pinned registration/getter source checks, not runtime
popularity or an assertion that the module is installed on an audited host.

## Contributor checklist

1. Pin source registration tables and every relevant getter, including HTTP/stream
   unions, build flags, byte copying, formatting and error/missing branches.
2. Separate fixed names from configurable destinations and writable inputs.
   Record output origin, default/empty/not_found behavior and scope. Never infer
   database types or script return values from names, examples or initializers.
3. Use existing literal/regex/trusted catalog representations and typed
   declarations. Prefer exact names; only use a prefix if all members share
   source-proven semantics. Opaque means `[\s\S]*`, never an empty trusted value.
4. Write regressions before the fix: alphabet allow/deny checks, missing/default
   cases, unsupported names, real splitting/SSRF/resolver findings, catalog
   overrides, include/order/scope/collision/audit isolation and provenance.
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
