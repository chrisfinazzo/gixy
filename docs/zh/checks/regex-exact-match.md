---
title: "正则可替换为精确匹配"
description: "将完全锚定的字面量正则 location 替换为精确匹配 location (=)，以获得更好的性能。"
---

# 正则 location 可替换为精确匹配

_Gixy Check ID: `regex_exact_match`_


当正则 `location` 匹配单个字面路径（使用 `^` 和 `$` 锚定，无特殊正则字符）时，可以将其替换为精确匹配 location (`=`) 以获得更好的性能。

NGINX 优先处理精确匹配 location，完全跳过正则引擎，因此速度明显更快。

错误示例：

```nginx
location ~ ^/api/health$ {
    return 200;
}
```

这里使用正则引擎来匹配实际上是固定字符串的内容。

正确示例：

```nginx
location = /api/health {
    return 200;
}
```

精确匹配 location 无需正则开销即可达到相同效果。

## 不适用的场景

此检查仅针对区分大小写的正则 location (`~`)。不区分大小写的正则 location (`~*`) 不会被标记，因为 `=` 修饰符始终区分大小写，转换会改变匹配行为。

包含任何正则特性（字符类、量词、分组、选择分支）的模式也不会被标记。

--8<-- "zh/snippets/nginx-extras-cta.md"
