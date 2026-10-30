---
title: "Переменные в директивах без подстановки"
description: "Обнаружение значений geo, split_clients и путей NGINX, где $переменная сохраняется как обычный текст."
---

# Переменные в директивах без подстановки

_Идентификатор проверки Gixy: `non_expanding_variable`_

Многие директивы NGINX подставляют значения переменных, поэтому легко решить,
что так работают все. Значения [`map`](https://nginx.org/ru/docs/http/ngx_http_map_module.html#map)
могут содержать переменные. Значения
[`geo`](https://nginx.org/ru/docs/http/ngx_http_geo_module.html) и
[`split_clients`](https://nginx.org/ru/docs/http/ngx_http_split_clients_module.html)
не могут: NGINX сохраняет `$binary_remote_addr` как строку из 19 символов
`$binary_remote_addr`. `nginx -t` не выдаёт предупреждений.

## Общая корзина ограничения запросов

Эта конфигурация выглядит как ограничение частоты для каждого клиента со
списком исключений:

```nginx
geo $limit_key {
    default   $binary_remote_addr;   # сохраняется буквально!
    127.0.0.1 "";
}
limit_req_zone $limit_key zone=dynamic:10m rate=5r/s;
```

Все клиенты вне списка исключений получают один и тот же ключ
`$binary_remote_addr` и делят **одну** корзину. Всплеск запросов одного
краулера исчерпывает лимит, и реальные посетители получают `503`. Gixy
сообщает об этом с уровнем HIGH и указывает директиву `limit_req_zone` или
`limit_conn_zone`, использующую ключ.

## Безопасная альтернатива

Пусть `geo` только классифицирует клиентов, а связанный `map` подставляет
переменную. Это шаблон списка исключений из
[руководства NGINX по ограничению частоты](https://blog.nginx.org/blog/rate-limiting-nginx):

```nginx
geo $limit {
    default   1;
    127.0.0.1 0;
    10.0.0.0/8 0;
}

map $limit $limit_key {
    0 "";
    1 $binary_remote_addr;
}

limit_req_zone $limit_key zone=dynamic:10m rate=5r/s;
```

Для `split_clients` используйте тот же подход: возвращайте буквальную метку и
сопоставляйте её со значением переменной в `map`.

## Пути без поддержки переменных

Эти директивы используют путь буквально и создают файлы или каталоги с `$` в
имени. Gixy сообщает о них с уровнем LOW:

| Директива | Буквальный аргумент |
|-----------|---------------------|
| `error_log` | путь к файлу |
| `client_body_temp_path`, `proxy_temp_path`, `fastcgi_temp_path`, `uwsgi_temp_path`, `scgi_temp_path` | каталог |
| `proxy_cache_path`, `fastcgi_cache_path`, `uwsgi_cache_path`, `scgi_cache_path` | каталог |

```nginx
# Создаёт файл с именем "$host.error.log"
error_log /var/log/nginx/$host.error.log;
```

`access_log` поддерживает переменные, поэтому о нём не сообщается. Переменные
также подставляются в значениях `map`, в `add_header`, `proxy_set_header`,
`root`, `alias`, `try_files`, `proxy_pass` и в ключе `limit_req_zone`.

--8<-- "ru/snippets/amplify-cta.md"
