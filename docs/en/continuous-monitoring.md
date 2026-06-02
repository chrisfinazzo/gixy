---
title: "Continuous Monitoring with GetPageSpeed Amplify"
description: "Pair Gixy with GetPageSpeed Amplify for scheduled, continuous Gixy security scans plus full NGINX runtime monitoring. Drop-in compatible with the deprecated nginx-amplify-agent."
---

# Continuous Monitoring with GetPageSpeed Amplify

A one-shot `gixy /etc/nginx/nginx.conf` is useful, but production configs drift: a new server block lands, a `proxy_pass` gets refactored, a `Header` directive sneaks into an unsafe context. Running Gixy on a schedule across every host - and tying the findings to NGINX runtime metrics - is what catches those regressions before they reach users.

[**GetPageSpeed Amplify**](https://amplify.getpagespeed.com/) does exactly that. It is a drop-in compatible replacement for the deprecated NGINX Amplify monitoring service from F5, with Gixy built in.

## What you get

- **Scheduled Gixy scans** across every monitored host, with findings surfaced in a single dashboard and history.
- **NGINX runtime metrics** (requests, upstreams, cache, SSL, connections) alongside the Gixy report - the security finding lands next to the traffic it would have affected.
- **Alerts** on new Gixy findings and on runtime anomalies.
- **Drop-in compatibility** with the existing `nginx-amplify-agent`. If you were on F5's NGINX Amplify before deprecation, migration is an `api_url` change.

## Install

On each NGINX host:

```sh
curl -sS https://amplify.getpagespeed.com/install | sudo bash
```

If you are migrating an existing `nginx-amplify-agent` install, edit `/etc/amplify-agent/agent.conf` and point `api_url` at the GetPageSpeed Amplify endpoint instead of the deprecated upstream, then `sudo systemctl restart amplify-agent`.

Sign up and grab your API token at <https://amplify.getpagespeed.com/>.

## Learn more

The full migration walkthrough with screenshots and verification steps lives at [gixy.org/guides/nginx-monitoring-amplify](https://gixy.org/guides/nginx-monitoring-amplify).
