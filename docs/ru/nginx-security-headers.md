---
title: "Руководство по настройке заголовков безопасности NGINX"
description: "Полное руководство по настройке HTTP-заголовков безопасности в NGINX: HSTS, CSP, X-Frame-Options, CORS и другие. Готовые примеры конфигурации."
keywords: "nginx заголовки безопасности, nginx HSTS, nginx Content-Security-Policy, nginx X-Frame-Options, nginx CORS, nginx add_header"
---

# Настройка заголовков безопасности NGINX

HTTP-заголовки безопасности — ваша первая линия защиты от клиентских атак, таких как XSS, clickjacking и внедрение данных. Это руководство охватывает все заголовки безопасности, которые следует настроить в NGINX.

!!! warning "Критически важно: Наследование заголовков в NGINX"
    Когда вы используете `add_header` в дочернем блоке (например, `location`), это **полностью переопределяет** все заголовки из родительских блоков. Это причина №1 ошибок конфигурации заголовков безопасности. Gixy может [обнаружить это автоматически](checks/add-header-redefinition.md).

---

## Быстрый старт: Основные заголовки

Скопируйте этот блок в конфигурацию вашего сервера для немедленной защиты:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name example.com;

    # === ОСНОВНЫЕ ЗАГОЛОВКИ БЕЗОПАСНОСТИ ===

    # HSTS — принудительный HTTPS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Предотвращение clickjacking
    add_header X-Frame-Options "SAMEORIGIN" always;

    # Предотвращение MIME type sniffing
    add_header X-Content-Type-Options "nosniff" always;

    # XSS-фильтр (устаревшие браузеры)
    add_header X-XSS-Protection "1; mode=block" always;

    # Контроль информации о referrer
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Content Security Policy (настройте под ваше приложение)
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; frame-ancestors 'self';" always;

    # Ограничение функций браузера
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;

    # ... остальная конфигурация
}
```

---

## Справочник по заголовкам

### 1. Strict-Transport-Security (HSTS)

Заставляет браузеры использовать HTTPS для всех будущих запросов к вашему домену.

**Предотвращаемая атака:** SSL stripping, атаки на понижение протокола

```nginx
# Базовый — 1 год
add_header Strict-Transport-Security "max-age=31536000" always;

# Включая поддомены
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Готов для списка preload
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

| Директива | Описание |
|-----------|----------|
| `max-age` | Время в секундах, в течение которого браузеры помнят об использовании HTTPS |
| `includeSubDomains` | Применять ко всем поддоменам |
| `preload` | Возможность включения в списки preload браузеров |

!!! danger "Перед использованием `includeSubDomains`"
    Убедитесь, что ВСЕ поддомены имеют действительный HTTPS. Поддомен с проблемами станет полностью недоступным.

!!! tip "Стратегия развёртывания"
    1. Начните с `max-age=300` (5 минут)
    2. Увеличьте до `max-age=86400` (1 день)
    3. Увеличьте до `max-age=604800` (1 неделя)
    4. Наконец установите `max-age=31536000` (1 год)

:white_check_mark: **Проверка Gixy:** [`hsts_header`](checks/hsts-header.md)

---

### 2. Content-Security-Policy (CSP)

Контролирует, какие ресурсы браузер может загружать. Самый мощный заголовок безопасности.

**Предотвращаемые атаки:** XSS, внедрение данных, clickjacking

```nginx
# Строгий CSP (ломает большинство сайтов — начните с этого для новых проектов)
add_header Content-Security-Policy "default-src 'self'" always;

# Типичное веб-приложение
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://api.example.com; frame-ancestors 'self';" always;

# Режим только отчётности (для тестирования)
add_header Content-Security-Policy-Report-Only "default-src 'self'; report-uri /csp-report" always;
```

**Основные директивы:**

| Директива | Контролирует | Пример |
|-----------|--------------|--------|
| `default-src` | Значение по умолчанию для других директив | `'self'` |
| `script-src` | Источники JavaScript | `'self' https://cdn.com` |
| `style-src` | Источники CSS | `'self' 'unsafe-inline'` |
| `img-src` | Источники изображений | `'self' data: https:` |
| `font-src` | Источники шрифтов | `'self' https://fonts.gstatic.com` |
| `connect-src` | XHR, WebSocket, fetch | `'self' https://api.example.com` |
| `frame-src` | Источники iframe | `'self'` |
| `frame-ancestors` | Кто может встраивать эту страницу | `'self'` |
| `base-uri` | Ограничение базового URL | `'self'` |
| `form-action` | Цели отправки форм | `'self'` |

**Значения источников:**

| Значение | Смысл |
|----------|-------|
| `'self'` | Тот же origin |
| `'none'` | Блокировать всё |
| `'unsafe-inline'` | Разрешить inline-скрипты/стили (избегайте если возможно) |
| `'unsafe-eval'` | Разрешить eval() (избегайте) |
| `https:` | Любой HTTPS URL |
| `data:` | Data URI |
| `'nonce-{random}'` | Конкретные inline-скрипты с соответствующим nonce |
| `'sha256-{hash}'` | Конкретные inline-скрипты с соответствующим хешем |

!!! tip "Рабочий процесс разработки CSP"
    1. Начните с `Content-Security-Policy-Report-Only`
    2. Мониторьте отчёты для определения нужных источников
    3. Постепенно ужесточайте политику
    4. Переключитесь на обязательный `Content-Security-Policy`

---

### 3. X-Frame-Options

Предотвращает встраивание вашей страницы в iframe (защита от clickjacking).

**Предотвращаемая атака:** Clickjacking, UI redressing

```nginx
# Запретить всё встраивание
add_header X-Frame-Options "DENY" always;

# Разрешить только тот же origin
add_header X-Frame-Options "SAMEORIGIN" always;

# Разрешить конкретный origin (устарело, используйте CSP frame-ancestors)
add_header X-Frame-Options "ALLOW-FROM https://trusted.com" always;
```

| Значение | Описание |
|----------|----------|
| `DENY` | Не может быть встроен никем |
| `SAMEORIGIN` | Может быть встроен только тем же origin |
| `ALLOW-FROM uri` | Устарело, используйте CSP |

!!! note "Современная альтернатива"
    Директива CSP `frame-ancestors` более гибкая и широко поддерживается:
    ```nginx
    add_header Content-Security-Policy "frame-ancestors 'self' https://trusted.com" always;
    ```

---

### 4. X-Content-Type-Options

Предотвращает атаки MIME type sniffing.

**Предотвращаемая атака:** Атаки на путаницу MIME-типов, drive-by downloads

```nginx
add_header X-Content-Type-Options "nosniff" always;
```

Единственное допустимое значение: `nosniff`. Всегда используйте его.

---

### 5. X-XSS-Protection

Включает встроенный XSS-фильтр браузера. В основном для устаревших браузеров.

**Предотвращаемая атака:** Reflected XSS (в старых браузерах)

```nginx
add_header X-XSS-Protection "1; mode=block" always;
```

| Значение | Описание |
|----------|----------|
| `0` | Отключить фильтр |
| `1` | Включить фильтр (санитизация) |
| `1; mode=block` | Включить фильтр (блокировка страницы) |

!!! note "Современные браузеры"
    Современные браузеры отказались от этого заголовка в пользу CSP. Всё ещё полезен для поддержки IE11 и старых браузеров.

---

### 6. Referrer-Policy

Контролирует, сколько информации о referrer отправляется с запросами.

**Предотвращаемая атака:** Утечка информации, нарушения приватности

```nginx
# Рекомендуется для большинства сайтов
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Максимальная приватность
add_header Referrer-Policy "no-referrer" always;

# Только same-origin
add_header Referrer-Policy "same-origin" always;
```

| Значение | Same-origin | Cross-origin (HTTPS→HTTPS) | Cross-origin (HTTPS→HTTP) |
|----------|-------------|---------------------------|---------------------------|
| `no-referrer` | Ничего | Ничего | Ничего |
| `same-origin` | Полный URL | Ничего | Ничего |
| `strict-origin` | Только origin | Только origin | Ничего |
| `strict-origin-when-cross-origin` | Полный URL | Только origin | Ничего |
| `origin-when-cross-origin` | Полный URL | Только origin | Только origin |

---

### 7. Permissions-Policy (ранее Feature-Policy)

Ограничивает доступ к функциям и API браузера.

**Предотвращаемая атака:** Нежелательный доступ к функциям, нарушения приватности

```nginx
# Отключить все чувствительные функции
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()" always;

# Разрешить определённые функции для same origin
add_header Permissions-Policy "geolocation=(self), camera=(self), microphone=()" always;

# Разрешить функции для конкретных origins
add_header Permissions-Policy "geolocation=(self https://maps.example.com)" always;
```

**Распространённые функции:**

| Функция | Описание |
|---------|----------|
| `geolocation` | Доступ к GPS/местоположению |
| `camera` | Доступ к камере |
| `microphone` | Доступ к микрофону |
| `payment` | Payment Request API |
| `usb` | Доступ к USB-устройствам |
| `fullscreen` | Fullscreen API |
| `autoplay` | Автовоспроизведение медиа |
| `display-capture` | Захват экрана |

---

### 8. Cross-Origin заголовки

Контролируют кросс-origin доступ к ресурсам.

#### Cross-Origin-Embedder-Policy (COEP)

```nginx
# Требовать CORS/CORP для всех ресурсов
add_header Cross-Origin-Embedder-Policy "require-corp" always;

# Режим без учётных данных
add_header Cross-Origin-Embedder-Policy "credentialless" always;
```

#### Cross-Origin-Opener-Policy (COOP)

```nginx
# Изолировать контекст браузинга
add_header Cross-Origin-Opener-Policy "same-origin" always;

# Разрешить всплывающие окна, но изолировать
add_header Cross-Origin-Opener-Policy "same-origin-allow-popups" always;
```

#### Cross-Origin-Resource-Policy (CORP)

```nginx
# Только same-origin может загружать этот ресурс
add_header Cross-Origin-Resource-Policy "same-origin" always;

# Same-site может загружать
add_header Cross-Origin-Resource-Policy "same-site" always;

# Любой origin может загружать
add_header Cross-Origin-Resource-Policy "cross-origin" always;
```

!!! info "Когда вам это нужно"
    Эти заголовки требуются для функций вроде `SharedArrayBuffer` и таймеров высокого разрешения. Большинству сайтов они не нужны.

---

## Конфигурация CORS

Для API, которые должны принимать кросс-origin запросы:

```nginx
# Простой CORS — разрешить все origins (только для публичных API)
location /api/ {
    add_header Access-Control-Allow-Origin "*" always;
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;

    if ($request_method = OPTIONS) {
        return 204;
    }
}

# CORS с конкретным origin
location /api/ {
    set $cors_origin "";
    if ($http_origin ~* "^https://(www\.)?example\.com$") {
        set $cors_origin $http_origin;
    }

    add_header Access-Control-Allow-Origin $cors_origin always;
    add_header Access-Control-Allow-Credentials "true" always;
    add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Content-Type, Authorization, X-Requested-With" always;
    add_header Access-Control-Max-Age "86400" always;

    if ($request_method = OPTIONS) {
        return 204;
    }
}
```

!!! danger "Никогда не используйте `*` с учётными данными"
    `Access-Control-Allow-Origin: *` нельзя использовать с `Access-Control-Allow-Credentials: true`. Это ограничение безопасности браузера.

---

## Решение проблемы наследования заголовков

### Проблема

```nginx
server {
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    location /api {
        add_header Access-Control-Allow-Origin "*" always;
        # X-Frame-Options и X-Content-Type-Options теперь ИСЧЕЗЛИ!
    }
}
```

### Решение 1: Используйте `include` для общих заголовков

```nginx
# /etc/nginx/snippets/security-headers.conf
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

```nginx
server {
    include /etc/nginx/snippets/security-headers.conf;

    location /api {
        include /etc/nginx/snippets/security-headers.conf;
        add_header Access-Control-Allow-Origin "*" always;
    }
}
```

### Решение 2: Используйте модуль `headers-more`

```nginx
# Установить заголовки на уровне http, которые не будут переопределены
more_set_headers "X-Frame-Options: SAMEORIGIN";
more_set_headers "X-Content-Type-Options: nosniff";
```

### Решение 3: Используйте `map` для динамических заголовков

```nginx
http {
    map $uri $security_headers {
        default "SAMEORIGIN";
        ~^/embed "ALLOW-FROM https://trusted.com";
    }

    server {
        add_header X-Frame-Options $security_headers always;
    }
}
```

:white_check_mark: **Проверка Gixy:** Gixy [`add_header_redefinition`](checks/add-header-redefinition.md) автоматически обнаруживает, когда заголовки, определённые в родительских блоках, случайно очищаются в дочерних блоках.

---

## Полный пример конфигурации

```nginx
http {
    # === ГЛОБАЛЬНЫЕ ЗАГОЛОВКИ БЕЗОПАСНОСТИ ===
    # Применяются ко всем серверам, если не переопределены

    # Примечание: Они будут очищены, если любой location использует add_header
    # Используйте паттерн include для согласованного применения

    server {
        listen 443 ssl;
        http2 on;
        server_name example.com;

        # Конфигурация SSL
        ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;

        # Включение заголовков безопасности в каждом контексте
        include /etc/nginx/snippets/security-headers.conf;

        root /var/www/example.com;
        index index.html;

        location / {
            include /etc/nginx/snippets/security-headers.conf;
            try_files $uri $uri/ =404;
        }

        location /api/ {
            include /etc/nginx/snippets/security-headers.conf;

            # Специфичные для API заголовки
            add_header Access-Control-Allow-Origin "https://app.example.com" always;
            add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE" always;

            proxy_pass http://backend;
        }

        location /embed/ {
            include /etc/nginx/snippets/security-headers.conf;

            # Переопределение политики фреймов для эндпоинта встраивания
            add_header X-Frame-Options "" always;  # Очистить значение по умолчанию
            add_header Content-Security-Policy "frame-ancestors https://partner.com" always;
        }
    }
}
```

**`/etc/nginx/snippets/security-headers.conf`:**

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

---

## Тестирование ваших заголовков

### Онлайн-инструменты

- [SecurityHeaders.com](https://securityheaders.com/) — Полный анализ заголовков
- [Mozilla Observatory](https://observatory.mozilla.org/) — Оценка безопасности
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/) — Анализ политики CSP

### Командная строка

```bash
# Проверка всех заголовков ответа
curl -I https://example.com

# Проверка конкретного заголовка
curl -s -I https://example.com | grep -i "strict-transport"

# Проверка с подробным выводом
curl -v https://example.com 2>&1 | grep -i "< "
```

### DevTools браузера

1. Откройте DevTools (F12)
2. Перейдите на вкладку Network
3. Нажмите на любой запрос
4. Посмотрите Response Headers

---

## Распространённые ошибки

### 1. Забыли `always`

```nginx
# ПЛОХО: Добавляется только при успешных ответах
add_header X-Frame-Options "SAMEORIGIN";

# ХОРОШО: Добавляется при всех ответах, включая ошибки
add_header X-Frame-Options "SAMEORIGIN" always;
```

### 2. Неправильный CSP для API

```nginx
# ПЛОХО: CSP с 'self' блокирует ответы API
location /api/ {
    add_header Content-Security-Policy "default-src 'self'" always;
}

# ХОРОШО: Другой или никакой CSP для API
location /api/ {
    # API обычно не нужен CSP
}
```

### 3. HSTS на HTTP

```nginx
# ПЛОХО: HSTS на порту 80 (бесполезно и странно)
server {
    listen 80;
    add_header Strict-Transport-Security "max-age=31536000" always;
}

# ХОРОШО: HSTS только на HTTPS
server {
    listen 443 ssl;
    add_header Strict-Transport-Security "max-age=31536000" always;
}
```

---

## Связанные ресурсы

- [Полное руководство по усилению безопасности NGINX](nginx-hardening-guide.md)
- [Чек-лист безопасности NGINX](nginx-security-checklist.md)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)

--8<-- "ru/snippets/nginx-extras-cta.md"
