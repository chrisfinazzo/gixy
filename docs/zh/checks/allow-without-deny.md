---
title: "有 allow 无 deny"
description: "指出仅有 allow 而无 deny all 等于默认放行，可能导致误开放的访问控制。文章展示完整白名单规则、顺序要求与常见误区，帮助快速修正。适用于安全审计与上线前自检，帮助团队统一配置规范、减少误配并降低风险。"
---

# `allow` 未配套 `deny`

当某个配置块包含 `allow` 指令（指定某个 IP 或网段）时，通常也应该包含 `deny all;` 指令（或在其他位置进行强制）。
**否则，基本上就没有任何访问限制。**

## 错误示例

```nginx
location / {
      root /var/www/;
      allow 10.0.0.0/8;
      . . .
}
```

--8<-- "zh/snippets/amplify-cta.md"

## 正确示例

```nginx
location / {
      root /var/www/;
      allow 10.0.0.0/8;
      deny all;
      . . .
}
```
