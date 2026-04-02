---
title: "Чек-лист безопасности NGINX 2026"
description: "Чек-лист для аудита безопасности NGINX. 40+ пунктов по SSL/TLS, заголовкам, контролю доступа и лучшим практикам конфигурации."
keywords: "чек-лист безопасности nginx, аудит nginx, проверка безопасности nginx, hardening nginx, защита nginx"
---

# Чек-лист безопасности NGINX

Полный, практический чек-лист для защиты вашего сервера NGINX. Используйте его для аудитов безопасности, проверок соответствия требованиям или усиления защиты новых развёртываний.

!!! tip "Автоматизируйте этот чек-лист"
    Вместо ручной проверки каждого пункта запустите `gixy /etc/nginx/nginx.conf` для автоматического обнаружения многих из этих проблем. [Подробнее →](index.md)

---

## Версия и раскрытие информации

- [ ] **Скрыть версию NGINX** — Установите `server_tokens off;` в блоке http
- [ ] **Пользовательские страницы ошибок** — Замените стандартные страницы ошибок, которые могут раскрывать информацию о версии
- [ ] **Удалить заголовок Server** — Используйте `more_clear_headers Server;` (требуется модуль headers-more)
- [ ] **Скрыть версию PHP** — Установите `expose_php = Off` в php.ini

??? example "Конфигурация"
    ```nginx
    http {
        server_tokens off;

        # Пользовательские страницы ошибок
        error_page 404 /custom_404.html;
        error_page 500 502 503 504 /custom_50x.html;
    }
    ```

:white_check_mark: **Проверка Gixy:** [`version_disclosure`](checks/version-disclosure.md)

---

## Конфигурация SSL/TLS

- [ ] **Отключить устаревшие протоколы** — Разрешить только TLSv1.2 и TLSv1.3
- [ ] **Использовать надёжные шифры** — Следуйте конфигурации Mozilla Intermediate или Modern
- [ ] **Отключить слабые шифры** — Без RC4, DES, 3DES, EXPORT, NULL
- [ ] **Включить OCSP stapling** — Уменьшает задержку и улучшает приватность
- [ ] **Настроить возобновление сессий** — Используйте `ssl_session_cache` и `ssl_session_tickets`
- [ ] **Использовать DH-параметры 2048+ бит** — Сгенерируйте командой `openssl dhparam -out dhparam.pem 4096`
- [ ] **Действительные сертификаты** — Проверьте срок действия, полноту цепочки

??? example "Конфигурация"
    ```nginx
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ```

:white_check_mark: **Проверка Gixy:** [`weak_ssl_tls`](checks/weak-ssl-tls.md)

---

## Заголовки безопасности

- [ ] **HSTS включён** — `Strict-Transport-Security` с соответствующим max-age
- [ ] **X-Frame-Options** — Установлен в `DENY` или `SAMEORIGIN`
- [ ] **X-Content-Type-Options** — Установлен в `nosniff`
- [ ] **X-XSS-Protection** — Установлен в `1; mode=block`
- [ ] **Referrer-Policy** — Установлена соответствующая политика для вашего случая
- [ ] **Content-Security-Policy** — Определены разрешённые источники контента
- [ ] **Permissions-Policy** — Ограничен доступ к функциям браузера
- [ ] **Заголовки во всех контекстах** — Проверьте, что заголовки не теряются в блоках location

??? example "Конфигурация"
    ```nginx
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self';" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    ```

:white_check_mark: **Проверки Gixy:** [`hsts_header`](checks/hsts-header.md), [`add_header_redefinition`](checks/add-header-redefinition.md)

---

## Конфигурация хоста и сервера

- [ ] **Определён сервер по умолчанию** — Отклоняет запросы с неизвестными Host-заголовками
- [ ] **Сервер по умолчанию возвращает 444** — Закрывает соединение без ответа
- [ ] **Каждый vhost имеет явный server_name** — Без catch-all конфигураций
- [ ] **Редирект HTTP на HTTPS** — Перенаправляет весь HTTP-трафик на HTTPS
- [ ] **Без wildcard server_name в продакшене** — Используйте явные имена хостов

??? example "Конфигурация"
    ```nginx
    # Сервер по умолчанию для отклонения неизвестных хостов
    server {
        listen 80 default_server;
        listen 443 ssl default_server;
        server_name _;
        ssl_certificate /etc/nginx/ssl/dummy.crt;
        ssl_certificate_key /etc/nginx/ssl/dummy.key;
        return 444;
    }

    # Редирект HTTP на HTTPS
    server {
        listen 80;
        server_name example.com;
        return 301 https://$server_name$request_uri;
    }
    ```

:white_check_mark: **Проверки Gixy:** [`host_spoofing`](checks/host-spoofing.md), [`default_server_flag`](checks/default-server-flag.md)

---

## Контроль доступа

- [ ] **Полные правила allow/deny** — Каждый блок `allow` заканчивается `deny all;`
- [ ] **Защита конфиденциальных файлов** — Блокировка доступа к `.git`, `.env`, `.htaccess` и т.д.
- [ ] **Защита файлов резервных копий** — Блокировка `.bak`, `.old`, `.swp`, `.tmp` файлов
- [ ] **Админ-зона ограничена** — Доступ ограничен по IP или аутентификации
- [ ] **Ограничения директории загрузок** — Отключено выполнение PHP/скриптов в путях загрузки
- [ ] **Return не обходит контроль доступа** — Учитывайте порядок обработки директив

??? example "Конфигурация"
    ```nginx
    # Блокировка конфиденциальных файлов
    location ~ /\. {
        deny all;
    }

    location ~* \.(git|svn|env|htaccess|htpasswd)$ {
        deny all;
    }

    # Админ-зона
    location /admin {
        allow 10.0.0.0/8;
        deny all;
        auth_basic "Admin Area";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }

    # Загрузки — без выполнения скриптов
    location /uploads {
        location ~ \.(php|py|pl|cgi)$ {
            deny all;
        }
    }
    ```

:white_check_mark: **Проверки Gixy:** [`allow_without_deny`](checks/allow-without-deny.md), [`return_bypasses_allow_deny`](checks/return-bypasses-allow-deny.md)

---

## Обработка путей и файлов

- [ ] **Завершающий слэш в alias** — Location с `alias` должен заканчиваться `/`
- [ ] **Без пользовательского контроля путей** — Не интерполируйте пользовательский ввод в путях к файлам
- [ ] **Проверьте root vs alias** — Понимайте разницу
- [ ] **Ограничьте область try_files** — Будьте осторожны с `try_files` и пользовательским вводом

??? example "Конфигурация"
    ```nginx
    # ПРАВИЛЬНО: завершающий слэш в обоих
    location /static/ {
        alias /var/www/static/;
    }

    # АЛЬТЕРНАТИВА: используйте root вместо alias
    location /static/ {
        root /var/www;
    }
    ```

:white_check_mark: **Проверки Gixy:** [`alias_traversal`](checks/alias-traversal.md), [`try_files_is_evil_too`](checks/try-files-is-evil-too.md)

---

## Конфигурация прокси

- [ ] **Без пользовательского контроля proxy_pass** — Жёстко задавайте upstream-серверы
- [ ] **Внутренние location защищены** — Используйте директиву `internal;`
- [ ] **Правильная пересылка заголовков** — Установите Host, X-Real-IP, X-Forwarded-For
- [ ] **Ограничения таймаутов** — Настройте connect, send, read таймауты
- [ ] **Resolver настроен для переменных** — Требуется при использовании переменных в proxy_pass

??? example "Конфигурация"
    ```nginx
    upstream backend {
        server 127.0.0.1:8080;
        keepalive 32;
    }

    location /api/ {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    ```

:white_check_mark: **Проверки Gixy:** [`ssrf`](checks/ssrf.md), [`missing_resolver`](checks/missing-resolver.md), [`proxy_pass_normalized`](checks/proxy-pass-normalized.md)

---

## Rate Limiting и защита от DoS

- [ ] **Ограничения соединений** — Используйте `limit_conn_zone` и `limit_conn`
- [ ] **Ограничения скорости запросов** — Используйте `limit_req_zone` и `limit_req`
- [ ] **Строгие лимиты для эндпоинтов авторизации** — Меньшие лимиты для login, регистрации
- [ ] **Ограничение размера тела запроса** — Установите соответствующий `client_max_body_size`
- [ ] **Ограничения буфера заголовков** — Настройте `large_client_header_buffers`
- [ ] **Значения таймаутов** — Установите разумные client_body_timeout, client_header_timeout

??? example "Конфигурация"
    ```nginx
    http {
        limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
        limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
        limit_conn_zone $binary_remote_addr zone=addr:10m;

        client_max_body_size 10m;
        client_body_timeout 12s;
        client_header_timeout 12s;
        large_client_header_buffers 4 16k;

        server {
            limit_req zone=general burst=20 nodelay;
            limit_conn addr 10;

            location /login {
                limit_req zone=login burst=5 nodelay;
            }
        }
    }
    ```

---

## Логирование и мониторинг

- [ ] **Логирование ошибок включено** — Никогда не используйте `error_log off;`
- [ ] **Логирование доступа включено** — Логируйте все запросы с полезной информацией
- [ ] **Формат логов для безопасности** — Включайте IP клиента, user agent, время ответа
- [ ] **Ротация логов настроена** — Используйте logrotate для управления файлами логов
- [ ] **Мониторинг логов настроен** — Пересылка в SIEM или систему мониторинга

??? example "Конфигурация"
    ```nginx
    log_format security '$remote_addr - $remote_user [$time_local] '
                        '"$request" $status $body_bytes_sent '
                        '"$http_referer" "$http_user_agent" '
                        '$request_time $upstream_response_time';

    access_log /var/log/nginx/access.log security;
    error_log /var/log/nginx/error.log warn;
    ```

:white_check_mark: **Проверка Gixy:** [`error_log_off`](checks/error-log-off.md)

---

## Гигиена конфигурации

- [ ] **Без `if` в блоках location** — Используйте `map` или `try_files` вместо этого, когда возможно
- [ ] **Валидные regex-паттерны** — Тестируйте все regex с помощью `nginx -t`
- [ ] **Якоря в regex** — Используйте `^` и `$` для предотвращения частичных совпадений
- [ ] **Без уязвимостей ReDoS** — Избегайте катастрофического возврата
- [ ] **Правильные значения по умолчанию в map** — Всегда определяйте значения по умолчанию в блоках map
- [ ] **Комментарии в конфигурации** — Документируйте неочевидные конфигурации

:white_check_mark: **Проверки Gixy:** [`if_is_evil`](checks/if-is-evil.md), [`invalid_regex`](checks/invalid-regex.md), [`unanchored_regex`](checks/unanchored-regex.md), [`regex_redos`](checks/regex-redos.md), [`hash_without_default`](checks/hash-without-default.md)

---

## Производительность и ограничения ресурсов

- [ ] **Worker-процессы** — Установите `auto` или количество ядер CPU
- [ ] **Worker-соединения** — Установите на основе ожидаемой нагрузки (обычно 1024-4096)
- [ ] **Лимиты файловых дескрипторов** — Убедитесь, что `worker_rlimit_nofile` соответствует системным лимитам
- [ ] **Настройка keepalive** — Установите соответствующие `keepalive_timeout` и `keepalive_requests`
- [ ] **Gzip включён** — Сжимайте текстовые ответы
- [ ] **Настройка буферов** — Оптимизируйте proxy и fastcgi буферы

:white_check_mark: **Проверки Gixy:** [`worker_rlimit_nofile_vs_connections`](checks/worker-rlimit-nofile-vs-connections.md), [`low_keepalive_requests`](checks/low-keepalive-requests.md)

---

## Безопасность файловой системы

- [ ] **Права на файлы конфигурации** — `chmod 640 /etc/nginx/nginx.conf`
- [ ] **Права на приватные ключи** — `chmod 600` для SSL-ключей
- [ ] **Владение** — Конфигурация принадлежит root, логи — www-data
- [ ] **SELinux/AppArmor** — Настройте политики MAC, если включены
- [ ] **Без директорий с правами записи для всех** — Проверьте права document root

```bash
# Проверка и исправление прав
chmod 640 /etc/nginx/nginx.conf
chmod 750 /etc/nginx/conf.d
chmod 600 /etc/nginx/ssl/*.key
chown -R root:root /etc/nginx
chown -R www-data:www-data /var/log/nginx
```

---

## Валидация и тестирование

- [ ] **Тест синтаксиса конфигурации** — Запускайте `nginx -t` после каждого изменения
- [ ] **Сканирование безопасности с Gixy** — Запускайте `gixy /etc/nginx/nginx.conf`
- [ ] **Тест SSL Labs** — Оценка A или A+ на [ssllabs.com/ssltest](https://www.ssllabs.com/ssltest/)
- [ ] **Тест заголовков безопасности** — Проверка на [securityheaders.com](https://securityheaders.com/)
- [ ] **Mozilla Observatory** — Проверка на [observatory.mozilla.org](https://observatory.mozilla.org/)

---

## Команды для быстрой проверки

```bash
# Тест синтаксиса конфигурации
nginx -t

# Сканирование безопасности с Gixy
gixy /etc/nginx/nginx.conf

# Проверка полного дампа конфигурации
nginx -T

# Тест конкретного файла конфигурации
nginx -t -c /path/to/nginx.conf

# Перезагрузка после изменений
nginx -s reload
```

---

## Скачать этот чек-лист

Распечатайте эту страницу или сохраните как PDF для офлайн-использования. Для автоматической проверки используйте Gixy:

```bash
pip install gixy-ng
gixy /etc/nginx/nginx.conf --format json > audit-results.json
```

См. [Руководство по интеграции CI/CD](ci-cd-integration.md) для автоматических проверок безопасности в вашем пайплайне.

---

## Связанные ресурсы

- [Полное руководство по усилению безопасности NGINX](nginx-hardening-guide.md) — Подробные объяснения и конфигурации
- [Руководство по заголовкам безопасности](nginx-security-headers.md) — Глубокое погружение в HTTP-заголовки безопасности
- [Документация Gixy](index.md) — Полный список автоматических проверок
- [Онлайн-проверка NGINX](https://www.getpagespeed.com/check-nginx-config) — Вставьте вашу конфигурацию для мгновенного анализа

--8<-- "ru/snippets/nginx-extras-cta.md"
