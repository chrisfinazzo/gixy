---
title: "Полное руководство по усилению безопасности NGINX 2026"
description: "Пошаговое руководство по защите NGINX. SSL/TLS, заголовки безопасности, контроль доступа, rate limiting и другие настройки. Автоматизация проверок с Gixy."
keywords: "nginx безопасность, nginx hardening, защита nginx, настройка безопасности nginx, усиление защиты nginx"
---

# Полное руководство по усилению безопасности NGINX

Это подробное руководство охватывает всё необходимое для защиты вашего сервера NGINX от распространённых атак и ошибок конфигурации. Каждый раздел включает описание уязвимости, способ исправления и способ автоматического обнаружения с помощью Gixy.

!!! tip "Автоматизируйте проверки безопасности"
    Не проверяйте nginx.conf вручную — запустите `gixy /etc/nginx/nginx.conf` для автоматического обнаружения этих проблем. [Начать работу →](index.md)

---

## 1. Скрытие версии NGINX

**Уровень риска:** Средний
**Вектор атаки:** Раскрытие информации помогает атакующим нацелиться на известные CVE

По умолчанию NGINX раскрывает номер своей версии в HTTP-заголовках ответа и на страницах ошибок. Это помогает злоумышленникам определить, какие уязвимости применимы к вашему серверу.

### Уязвимая конфигурация

```nginx
http {
    # server_tokens по умолчанию 'on', если не указано
    server {
        listen 80;
        server_name example.com;
    }
}
```

Заголовок ответа: `Server: nginx/1.24.0`

### Защищённая конфигурация

```nginx
http {
    server_tokens off;  # Скрыть версию в заголовках и страницах ошибок

    server {
        listen 80;
        server_name example.com;
    }
}
```

Заголовок ответа: `Server: nginx`

!!! success "Обнаружение Gixy"
    Проверка Gixy [`version_disclosure`](checks/version-disclosure.md) автоматически обнаруживает как явное `server_tokens on;`, так и отсутствующие директивы, которые по умолчанию раскрывают версию.

---

## 2. Настройка безопасного SSL/TLS

**Уровень риска:** Критический
**Вектор атаки:** POODLE, BEAST, Sweet32, атаки на понижение версии

Слабая конфигурация SSL/TLS может позволить злоумышленникам расшифровать трафик или провести атаки «человек посередине».

### Уязвимая конфигурация

```nginx
server {
    listen 443 ssl;
    ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;  # Устаревшие протоколы
    ssl_ciphers ALL;  # Включает слабые шифры
}
```

### Защищённая конфигурация (Mozilla Intermediate)

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name example.com;

    # Только современные протоколы
    ssl_protocols TLSv1.2 TLSv1.3;

    # Надёжные наборы шифров (Mozilla Intermediate)
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;

    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;

    # curl https://ssl-config.mozilla.org/ffdhe2048.txt > /etc/nginx/ffdhe2048.txt
    # или
    # openssl dhparam -out /etc/nginx/ffdhe2048.txt 2048
    ssl_dhparam /etc/nginx/ffdhe2048.txt

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
}
```

!!! success "Обнаружение Gixy"
    Проверка Gixy [`weak_ssl_tls`](checks/weak-ssl-tls.md) обнаруживает небезопасные протоколы (SSLv2, SSLv3, TLSv1.0, TLSv1.1) и слабые наборы шифров (RC4, DES, 3DES, EXPORT, NULL).

---

## 3. Включение HTTP Strict Transport Security (HSTS)

**Уровень риска:** Высокий
**Вектор атаки:** SSL stripping, атаки на понижение версии

HSTS указывает браузерам всегда использовать HTTPS, предотвращая атаки SSL stripping.

### Уязвимая конфигурация

```nginx
server {
    listen 443 ssl;
    # Отсутствует заголовок HSTS — уязвим для SSL stripping
}
```

### Защищённая конфигурация

```nginx
server {
    listen 443 ssl;
    http2 on;

    # HSTS с max-age 1 год и включением поддоменов
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}
```

!!! warning "Особенности HSTS"
    - Начните с короткого `max-age` (например, 300) во время тестирования
    - Добавляйте `preload` только если готовы отправить заявку в [список HSTS preload](https://hstspreload.org/)
    - Убедитесь, что ВСЕ поддомены поддерживают HTTPS перед использованием `includeSubDomains`

!!! success "Обнаружение Gixy"
    Проверка Gixy [`hsts_header`](checks/hsts-header.md) обнаруживает отсутствующие или неправильно настроенные заголовки HSTS на HTTPS-серверах.

---

## 4. Добавление заголовков безопасности

**Уровень риска:** Средний-Высокий
**Вектор атаки:** XSS, clickjacking, атаки на MIME-типы

Заголовки безопасности обеспечивают глубокую защиту от различных клиентских атак.

### Защищённая конфигурация

```nginx
server {
    listen 443 ssl;
    http2 on;

    # Предотвращение clickjacking
    add_header X-Frame-Options "SAMEORIGIN" always;

    # Предотвращение MIME type sniffing
    add_header X-Content-Type-Options "nosniff" always;

    # Защита от XSS (устаревшие браузеры)
    add_header X-XSS-Protection "1; mode=block" always;

    # Политика Referrer
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Content Security Policy (настройте под ваше приложение)
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;

    # Permissions Policy
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
}
```

!!! danger "Предупреждение о наследовании заголовков"
    Директивы `add_header` в дочерних блоках **полностью переопределяют** заголовки родительского блока. Если вы добавляете любой заголовок в блоке location, вы должны заново добавить ВСЕ заголовки безопасности.

!!! success "Обнаружение Gixy"
    Проверка Gixy [`add_header_redefinition`](checks/add-header-redefinition.md) обнаруживает, когда дочерние блоки случайно очищают заголовки безопасности, определённые в родительских блоках.

---

## 5. Предотвращение подмены Host-заголовка

**Уровень риска:** Высокий
**Вектор атаки:** Отравление кэша, отравление сброса пароля, SSRF

Без сервера по умолчанию, который отклоняет неизвестные хосты, злоумышленники могут отправлять запросы с произвольными Host-заголовками.

### Уязвимая конфигурация

```nginx
server {
    listen 80;
    server_name example.com;
    # Первый блок server становится сервером по умолчанию — принимает любой Host-заголовок
}
```

### Защищённая конфигурация

```nginx
# Сервер по умолчанию, отклоняющий неизвестные хосты
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    server_name _;

    ssl_certificate /path/to/dummy.crt;
    ssl_certificate_key /path/to/dummy.key;

    return 444;  # Закрыть соединение без ответа
}

# Ваш настоящий сервер
server {
    listen 80;
    listen 443 ssl;
    server_name example.com www.example.com;
    # ... ваша конфигурация
}
```

!!! success "Обнаружение Gixy"
    Проверки Gixy [`host_spoofing`](checks/host-spoofing.md) и [`default_server_flag`](checks/default-server-flag.md) обнаруживают отсутствие конфигурации сервера по умолчанию и потенциальные атаки на Host-заголовок.

---

## 6. Реализация контроля доступа

**Уровень риска:** Высокий
**Вектор атаки:** Несанкционированный доступ, раскрытие информации

Ограничьте доступ к конфиденциальным местоположениям и всегда используйте полные правила allow/deny.

### Уязвимая конфигурация

```nginx
location /admin {
    allow 192.168.1.0/24;
    # Отсутствует 'deny all' — другие IP всё ещё могут получить доступ!
}
```

### Защищённая конфигурация

```nginx
# Ограничение админ-зоны
location /admin {
    allow 10.0.0.0/8;
    allow 192.168.1.0/24;
    deny all;  # Всегда завершайте deny all
}

# Блокировка доступа к конфиденциальным файлам
location ~ /\. {
    deny all;
}

location ~* \.(git|svn|env|htaccess|htpasswd)$ {
    deny all;
}

# Блокировка доступа к файлам резервных копий
location ~* \.(bak|backup|old|orig|save|swp|tmp)$ {
    deny all;
}
```

!!! success "Обнаружение Gixy"
    Проверка Gixy [`allow_without_deny`](checks/allow-without-deny.md) обнаруживает неполные правила контроля доступа, которые не заканчиваются `deny all`.

---

## 7. Предотвращение Path Traversal с Alias

**Уровень риска:** Критический
**Вектор атаки:** Обход каталогов, произвольное чтение файлов

Директива `alias` подвержена уязвимостям обхода пути, когда location не заканчивается `/`.

### Уязвимая конфигурация

```nginx
location /static {
    alias /var/www/static/;  # УЯЗВИМО: отсутствует завершающий слэш в location
}
```

Атака: `GET /static../etc/passwd` → читает `/var/www/static/../etc/passwd` → `/var/www/etc/passwd`

### Защищённая конфигурация

```nginx
# Вариант 1: Добавьте завершающий слэш в location
location /static/ {
    alias /var/www/static/;
}

# Вариант 2: Используйте root вместо alias
location /static/ {
    root /var/www;
}
```

!!! success "Обнаружение Gixy"
    Проверка Gixy [`alias_traversal`](checks/alias-traversal.md) обнаруживает конфигурации alias, уязвимые для атак обхода пути.

---

## 8. Безопасные конфигурации прокси

**Уровень риска:** Критический
**Вектор атаки:** SSRF, HTTP request smuggling

Неправильно настроенные обратные прокси могут позволить атаки Server-Side Request Forgery (SSRF).

### Уязвимая конфигурация

```nginx
# Уязвимость SSRF — атакующий контролирует назначение прокси
location ~ /proxy/(.*)/(.*)/(.*)$ {
    proxy_pass $1://$2/$3;
}
```

### Защищённая конфигурация

```nginx
# Жёстко заданный upstream — нет пользовательского контроля
upstream backend {
    server 127.0.0.1:8080;
}

location /api/ {
    proxy_pass http://backend;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # Таймауты
    proxy_connect_timeout 60s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;
}
```

!!! success "Обнаружение Gixy"
    Проверка Gixy [`ssrf`](checks/ssrf.md) обнаруживает конфигурации прокси, где пользовательский ввод может контролировать назначение.

---

## 9. Rate Limiting и защита от DDoS

**Уровень риска:** Средний
**Вектор атаки:** DoS, брутфорс, исчерпание ресурсов

Реализуйте ограничение скорости для защиты от злоупотреблений и атак типа «отказ в обслуживании».

### Защищённая конфигурация

```nginx
http {
    # Определение зон ограничения скорости
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    limit_conn_zone $binary_remote_addr zone=addr:10m;

    # Ограничение размера тела запроса
    client_max_body_size 10m;
    client_body_buffer_size 128k;

    # Ограничение размера заголовков
    large_client_header_buffers 4 16k;

    server {
        # Общее ограничение скорости
        limit_req zone=general burst=20 nodelay;
        limit_conn addr 10;

        # Более строгие лимиты для эндпоинтов авторизации
        location /login {
            limit_req zone=login burst=5 nodelay;
        }
    }
}
```

---

## 10. Логирование и мониторинг

**Уровень риска:** Средний
**Вектор атаки:** Пропущенное обнаружение атак, нарушение соответствия требованиям

Правильное логирование необходимо для мониторинга безопасности и реагирования на инциденты.

### Уязвимая конфигурация

```nginx
http {
    error_log off;  # ОПАСНО: Нет логирования ошибок
}
```

### Защищённая конфигурация

```nginx
http {
    # Структурированное логирование для анализа безопасности
    log_format security '$remote_addr - $remote_user [$time_local] '
                        '"$request" $status $body_bytes_sent '
                        '"$http_referer" "$http_user_agent" '
                        '$request_time $upstream_response_time '
                        '$ssl_protocol $ssl_cipher';

    access_log /var/log/nginx/access.log security;
    error_log /var/log/nginx/error.log warn;

    server {
        # Логирование ответов 4xx/5xx для мониторинга безопасности
        access_log /var/log/nginx/security.log security if=$loggable;
    }
}

# Определение переменной loggable
map $status $loggable {
    ~^[23]  0;
    default 1;
}
```

!!! success "Обнаружение Gixy"
    Проверка Gixy [`error_log_off`](checks/error-log-off.md) обнаруживает опасные конфигурации, которые отключают логирование ошибок.

---

## 11. Отключение ненужных модулей

**Уровень риска:** Низкий-Средний
**Вектор атаки:** Уменьшение поверхности атаки

Скомпилируйте NGINX только с необходимыми модулями:

```bash
./configure \
    --without-http_autoindex_module \
    --without-http_ssi_module \
    --without-http_userid_module \
    --without-http_auth_basic_module \  # Только если не используется
    --without-http_mirror_module
```

Для готовых пакетов отключите во время выполнения, где это возможно:

```nginx
autoindex off;        # Отключить листинг директорий
ssi off;              # Отключить SSI, если не нужно
```

---

## 12. Права доступа к файлам и владение

**Уровень риска:** Средний
**Вектор атаки:** Повышение привилегий, несанкционированное изменение

```bash
# Установка правильного владельца
chown -R root:root /etc/nginx
chown -R www-data:www-data /var/log/nginx

# Ограничение доступа к конфигурации
chmod 640 /etc/nginx/nginx.conf
chmod 750 /etc/nginx/conf.d
chmod 640 /etc/nginx/conf.d/*

# Защита SSL-сертификатов
chmod 600 /etc/nginx/ssl/*.key
chmod 644 /etc/nginx/ssl/*.crt
```

---

## Полный шаблон защищённой конфигурации

Вот полный nginx.conf, включающий все вышеуказанные меры по усилению безопасности:

```nginx
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;

events {
    worker_connections 4096;
    multi_accept on;
    use epoll;
}

http {
    # Базовые настройки
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # Скрыть версию
    server_tokens off;

    # MIME-типы
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Зоны ограничения скорости
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    limit_conn_zone $binary_remote_addr zone=addr:10m;

    # Ограничения размера запроса
    client_max_body_size 10m;
    client_body_buffer_size 128k;
    large_client_header_buffers 4 16k;

    # Настройки SSL
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;

    # Логирование
    log_format security '$remote_addr - $remote_user [$time_local] '
                        '"$request" $status $body_bytes_sent '
                        '"$http_referer" "$http_user_agent"';

    access_log /var/log/nginx/access.log security;
    error_log /var/log/nginx/error.log warn;

    # Gzip-сжатие
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript application/xml;

    # Сервер по умолчанию для отклонения неизвестных хостов
    server {
        listen 80 default_server;
        listen 443 ssl default_server;
        server_name _;
        ssl_certificate /etc/nginx/ssl/dummy.crt;
        ssl_certificate_key /etc/nginx/ssl/dummy.key;
        return 444;
    }

    # Подключение конфигураций сайтов
    include /etc/nginx/conf.d/*.conf;
}
```

---

## Проверьте вашу конфигурацию с помощью Gixy

После реализации этих мер безопасности проверьте, что ваша конфигурация безопасна:

```bash
# Установка Gixy
pip install gixy-ng

# Сканирование конфигурации
gixy /etc/nginx/nginx.conf

# Сканирование со всеми include
gixy /etc/nginx/nginx.conf --config /etc/nginx/

# JSON-вывод для CI/CD
gixy /etc/nginx/nginx.conf --format json
```

См. [Руководство по интеграции CI/CD](ci-cd-integration.md) для автоматизации проверок безопасности в вашем пайплайне развёртывания.

---

## Следующие шаги

- [Чек-лист безопасности NGINX](nginx-security-checklist.md) — Краткий справочный чек-лист
- [Руководство по заголовкам безопасности](nginx-security-headers.md) — Подробное руководство по настройке заголовков
- [Все проверки безопасности Gixy](index.md) — Полный список автоматических проверок
- [Попробовать Gixy онлайн](https://www.getpagespeed.com/check-nginx-config) — Вставьте вашу конфигурацию для мгновенного анализа

--8<-- "ru/snippets/nginx-extras-cta.md"
