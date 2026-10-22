---
title: "if в location опасен"
description: "if в блоках location непредсказуем; применяйте безопасные альтернативы (return/rewrite/map)."
---

# Если в location — это плохо

_Gixy Check ID: `if_is_evil`_


Директива [`if`](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#if), **когда используется внутри location**, может работать не так, как ожидается, а в некоторых случаях приводить к segfault. Обычно лучше избегать её.

Альтернативы:
- [`return ...;`](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#return)
- [`rewrite ... last;`](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#rewrite)
- [`rewrite ... redirect;`](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#rewrite)
- [`rewrite ... permanent;`](https://nginx.org/en/docs/http/ngx_http_rewrite_module.html#rewrite)

Иногда имеет смысл использовать встроенные языки (например, [embedded perl](https://nginx.org/en/docs/http/ngx_http_perl_module.html) или [Lua](https://nginx-extras.getpagespeed.com/lua-scripting/)).

--8<-- "ru/snippets/amplify-cta.md"
