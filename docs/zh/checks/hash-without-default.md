---
title: "map/geo 未设 default"
description: "说明 map/geo 等哈希块必须配置安全的 default 值，否则未知键会落入不确定分支并绕过访问控制。文章解释常见误配场景与影响，并提供稳妥的默认值设置建议。适用于安全审计与上线前自检，帮助团队统一配置规范、减少误配并降低风险。"
---

# `map`/`geo` 等哈希块缺少默认值

_Gixy Check ID: `hash_without_default`_


`map` 与 `geo` 等哈希块应设置安全的 `default` 值。若缺省，未知键可能落入意料之外的状态，从而旁路安全控制。

## 不安全示例

```nginx
# 无 default → 未知键行为不可预测
map $request_uri $allowed {
    /admin 0;
}

# geo 无 default
geo $block_client {
    192.0.2.0/24 1;
}
```

## 更安全的替代方案

```nginx
# 提供安全默认值
map $request_uri $allowed {
    default 1;      # 默认拒绝
    /admin 0;       # 仅当后续逻辑显式设置时才允许
}

# 在 geo 中提供默认值
geo $block_client {
    default 0;      # 默认不阻止
    192.0.2.0/24 1; # 阻止这些
}
```

选择符合“最小权限”原则的默认值（控制访问时，默认拒绝）。

## 为什么重要

显式默认值让行为更可预测，并避免在新增键或输入异常时出现意外的允许/拒绝空洞。

--8<-- "zh/snippets/amplify-cta.md"
