---
title: "Regex Can Be Exact Match"
description: "Replace fully-anchored literal regex locations with exact-match locations for better performance."
---

# Regex Location Can Be Exact Match

_Gixy Check ID: `regex_exact_match`_


When a regex `location` matches a single literal path (anchored with `^` and `$`, no special regex characters), it can be replaced with an exact-match location (`=`) for better performance.

NGINX processes exact-match locations first and skips the regex engine entirely, making them significantly faster.

Incorrect:

```nginx
location ~ ^/api/health$ {
    return 200;
}
```

This uses the regex engine to match what is effectively a fixed string.

Correct:

```nginx
location = /api/health {
    return 200;
}
```

The exact-match location achieves the same result without regex overhead.

## When this check does not apply

This check only flags case-sensitive regex locations (`~`). Case-insensitive regex locations (`~*`) are not flagged because the `=` modifier is always case-sensitive, and converting would change matching behavior.

Patterns that contain any regex features (character classes, quantifiers, groups, alternation) are also not flagged.

--8<-- "en/snippets/nginx-extras-cta.md"
