---
title: "error_log Set to 'off'"
description: "Setting error_log off makes NGINX write to a file named 'off'. If you must disable logging, point it at /dev/null instead."
---

# error_log Set to 'off'

_Gixy Check ID: `error_log_off`_


A common misconception is that using the directive `error_log off` disables error logging.
Unlike the `access_log` directive, `error_log` does not accept an `off` parameter.
If you add `error_log` off to your configuration, NGINX will create a log file named “off” in the default configuration directory (typically `/etc/nginx`).

Disabling the error log is generally not advised, as it provides crucial information
for troubleshooting NGINX issues. However, if disk space is extremely limited and
there’s a risk that logging could fill up the available space, you might opt to
disable error logging. To do so, add the following directive in the main configuration
context:

```nginx
error_log /dev/null emerg;
```

Keep in mind that this setting takes effect only after NGINX reads and validates
the configuration file. Therefore, during startup or when reloading the configuration,
NGINX may still log errors to the default error log location (usually `/var/log/nginx/error.log`)
until validation is complete. To change the default log directory permanently, use the `--error-log-path` (or `-e`) option when starting NGINX.

--8<-- "en/snippets/amplify-cta.md"
