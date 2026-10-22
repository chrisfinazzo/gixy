---
title: "valid_referers 使用 none"
description: "说明 valid_referers 的 none 选项会放行无 Referer 请求，削弱防盗链或点击劫持防护。文章解释何时会触发放行，并给出更严格的白名单配置。适用于安全审计与上线前自检，帮助团队统一配置规范、减少误配并降低风险。"
---

# 在 valid_referers 中使用 `none`

_Gixy Check ID: `valid_referrers`_


模块 [ngx_http_referer_module](https://nginx.org/en/docs/http/ngx_http_referer_module.html) 可用于基于 `Referer` 阻止访问。
它常被用于设置 `X-Frame-Options`（防点击劫持），也可用于其他场景。

当在 `valid_referers` 中使用 `none` 时，可能导致意外放行或规则变得难以预测。

建议谨慎使用 `none`，并明确列举允许来源或采用更严格的匹配方式。

--8<-- "zh/snippets/amplify-cta.md"
