---
title: "worker_rlimit_nofile и worker_connections"
description: "Поднимите worker_rlimit_nofile минимум вдвое от worker_connections, чтобы не упираться в лимит дескрипторов."
---

# worker_rlimit_nofile должен быть ≥ 2× worker_connections

_Gixy Check ID: `worker_rlimit_nofile_vs_connections`_


Если `worker_rlimit_nofile` слишком мал относительно `worker_connections`, воркеры могут быстро упереться в лимит открытых файловых дескрипторов, что приведёт к сбоям.

## Рекомендация

- Установите `worker_rlimit_nofile` как минимум в два раза больше значения `worker_connections`.

--8<-- "ru/snippets/amplify-cta.md"
