---
title: "Открытая страница статуса"
description: "Защитите stub_status от публичного доступа: всегда ограничивайте его директивами allow/deny, чтобы избежать раскрытия информации."
---

# Открытая страница статуса

_Gixy Check ID: `status_page_exposed`_


Модуль `stub_status` отдаёт метрики сервера NGINX: число активных соединений, обработанных запросов и состояния соединений. Без ограничений по IP эта информация доступна всем и может помочь атакующему в разведке.

## Плохой пример

```nginx
location /status {
    stub_status;
}
```

Или с `allow`, но без `deny all`:

```nginx
location /status {
    stub_status;
    allow 10.0.0.0/8;
}
```

--8<-- "ru/snippets/amplify-cta.md"

## Хороший пример

```nginx
location = /nginx-status {
    stub_status on;
    allow 127.0.0.1;
    allow ::1;
    deny all;
}
```

Всегда сочетайте `stub_status` с явными директивами `allow` для доверенных IP-адресов и `deny all`, чтобы закрыть доступ всем остальным.
