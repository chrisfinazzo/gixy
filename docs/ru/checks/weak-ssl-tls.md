---
title: "Слабая конфигурация SSL/TLS"
description: "Отключите устаревший TLS и слабые шифры в NGINX. Перейдите на современные наборы шифров в стиле Mozilla для защиты от POODLE/BEAST/Sweet32."
---

# Слабая конфигурация SSL/TLS

_Идентификатор проверки Gixy: `weak_ssl_tls`_


## Обзор

Плагин `weak_ssl_tls` обнаруживает небезопасные конфигурации SSL/TLS, которые могут скомпрометировать безопасность зашифрованных соединений. Это включает устаревшие протоколы, слабые наборы шифров и выбор шифров на стороне клиента.

## Что обнаруживается

Выражение `ssl_ciphers` обрабатывается по порядку: `!` исключает набор
навсегда, `-` удаляет с возможностью повторного добавления, `+` в начале
только меняет порядок, а `+` внутри выражения задаёт пересечение. Для
неизвестных селекторов Gixy сообщает о возможном слабом наборе; локальная
сборка OpenSSL не используется как доказательство безопасности целевого сервера.

### 1. Небезопасные протоколы TLS
Обнаруживает использование устаревших протоколов, уязвимых для атак:

| Протокол | Статус | Уязвимости |
|----------|--------|-----------------|
| SSLv2 | ❌ Небезопасен | Множество критических уязвимостей |
| SSLv3 | ❌ Небезопасен | Атака POODLE |
| TLSv1.0 | ❌ Небезопасен | BEAST, POODLE, CRIME |
| TLSv1.1 | ❌ Небезопасен | Слабые шифры, нет AEAD |
| TLSv1.2 | ✅ Безопасен | Используйте с сильными шифрами |
| TLSv1.3 | ✅ Безопасен | Современный, рекомендуется |

### 2. Слабые наборы шифров
Обнаруживает наборы шифров, которых следует избегать:

- **NULL-шифры** — Шифрование отсутствует
- **EXPORT-шифры** — Намеренно ослаблены (40-56 бит)
- **DES/3DES** — Уязвимы для атаки Sweet32
- **RC4** — Взломанный потоковый шифр
- **Анонимные шифры (ADH/AECDH)** — Нет аутентификации
- **Шифры на основе MD5** — Слабая хеш-функция

### 3. Предпочтение шифров сервера
Обнаруживает, когда `ssl_prefer_server_ciphers` отключён, позволяя клиентам выбирать потенциально более слабые шифры.

## Примеры

### ❌ Плохо: Включены небезопасные протоколы
```nginx
server {
    listen 443 ssl;
    ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;  # SSLv3, TLSv1, TLSv1.1 небезопасны
}
```
**Проблема**: `Включены небезопасные протоколы: SSLv3, TLSv1, TLSv1.1`

### ❌ Плохо: Слабые шифры
```nginx
server {
    listen 443 ssl;
    ssl_ciphers ALL:RC4:DES:3DES;  # Включены слабые шифры
}
```
**Проблема**: `Обнаружены слабые шифры: RC4, DES, 3DES`

### ✅ Хорошо: Безопасная конфигурация
```nginx
server {
    listen 443 ssl;

    # Только современные протоколы
    ssl_protocols TLSv1.2 TLSv1.3;

    # Набор шифров Mozilla Intermediate
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    # Сервер выбирает шифр
    ssl_prefer_server_ciphers on;

    # HSTS проверяется отдельным плагином `hsts_header`.
}
```

## Рекомендуемая конфигурация

На основе [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/):

### Промежуточная конфигурация (Рекомендуется)
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
```

### Современная конфигурация (только TLSv1.3)
```nginx
ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers off;
```

## Почему это важно

Слабые конфигурации SSL/TLS подвергают ваш сервер:

1. **Атака POODLE** (SSLv3) — Позволяет расшифровывать защищённые соединения
2. **Атака BEAST** (TLSv1.0) — Позволяет расшифровывать HTTPS-cookie
3. **Атака Sweet32** (3DES) — Позволяет восстанавливать открытый текст из длительных соединений
4. **Смещение RC4** — Позволяет восстанавливать открытый текст из зашифрованных потоков
5. **Атаки понижения** — Принуждают использовать более слабые протоколы

## Тестирование вашей конфигурации

Используйте эти инструменты для проверки вашей конфигурации SSL/TLS:

- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- `openssl s_client -connect yoursite.com:443`

## Ссылки

- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [Mozilla Server Side TLS Guide](https://wiki.mozilla.org/Security/Server_Side_TLS)
- [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)

--8<-- "ru/snippets/nginx-extras-cta.md"
