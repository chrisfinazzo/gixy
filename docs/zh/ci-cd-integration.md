---
title: "CI/CD 集成"
description: "将 Gixy 集成到您的 CI/CD 流水线中，自动扫描 NGINX 配置的安全问题。支持 Jenkins、GitLab CI、GitHub Actions 等。"
---

# CI/CD 集成

Gixy 可以无缝集成到 CI/CD 流水线中，在 NGINX 安全配置错误进入生产环境之前捕获它们。

## Checkstyle XML 输出

对于 CI/CD 集成，使用 `--format checkstyle` 选项生成机器可读的 XML 输出：

```bash
gixy --format checkstyle /etc/nginx/nginx.conf > gixy-report.xml
```

Checkstyle XML 格式是静态分析工具广泛支持的标准，原生支持于：

- **Jenkins**（Warnings Next Generation 插件）
- **GitLab CI**（Code Quality 报告）
- **GitHub Actions**（通过 reviewdog、super-linter）
- **Bitbucket Pipelines**（Code Insights）
- **SonarQube**（外部问题导入）
- **许多 IDE**（IntelliJ、Eclipse、VS Code）

### 输出示例

```xml
<?xml version="1.0" encoding="UTF-8"?>
<checkstyle version="8.0">
  <file name="/etc/nginx/nginx.conf">
    <error line="10" column="1" severity="error"
           message="[ssrf] SSRF vulnerability: reason"
           source="gixy.ssrf"/>
  </file>
</checkstyle>
```

## GitHub Actions

```yaml
name: NGINX Security Scan

on: [push, pull_request]

jobs:
  gixy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Gixy
        run: pip install gixy-ng

      - name: Run Gixy
        run: gixy --format checkstyle nginx/*.conf > gixy-report.xml
        continue-on-error: true

      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: gixy-report
          path: gixy-report.xml
```

### 使用 reviewdog

对于 PR 内联评论，使用 [reviewdog](https://github.com/reviewdog/reviewdog)：

```yaml
- name: Run Gixy with reviewdog
  uses: reviewdog/action-setup@v1

- name: Gixy
  env:
    REVIEWDOG_GITHUB_API_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    gixy --format checkstyle nginx/*.conf | \
      reviewdog -f=checkstyle -reporter=github-pr-review
```

## GitLab CI

```yaml
gixy:
  stage: test
  image: python:3.11-slim
  before_script:
    - pip install gixy-ng
  script:
    - gixy --format checkstyle nginx/*.conf > gl-code-quality-report.xml
  artifacts:
    reports:
      codequality: gl-code-quality-report.xml
    when: always
```

## Jenkins

使用 [Warnings Next Generation 插件](https://plugins.jenkins.io/warnings-ng/)：

```groovy
pipeline {
    agent any
    stages {
        stage('NGINX Security Scan') {
            steps {
                sh 'pip install gixy-ng'
                sh 'gixy --format checkstyle /etc/nginx/*.conf > gixy-report.xml || true'
            }
            post {
                always {
                    recordIssues(
                        tools: [checkStyle(pattern: 'gixy-report.xml')]
                    )
                }
            }
        }
    }
}
```

## Docker

对于容器化流水线：

```bash
docker run --rm -v /path/to/nginx:/etc/nginx:ro \
  getpagespeed/gixy --format checkstyle /etc/nginx/nginx.conf
```

## 退出码

Gixy 使用退出码来指示扫描结果：

| 退出码 | 含义 |
|-----------|---------|
| 0 | 未发现问题 |
| 1 | 发现问题 |
| 2 | 配置错误 |

在您的 CI/CD 流水线中使用这些退出码在发现安全问题时中断构建：

```bash
gixy /etc/nginx/nginx.conf || exit 1
```

## Pre-commit 钩子

将 Gixy 添加到您的 pre-commit 配置：

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/dvershinin/gixy
    rev: v0.2.24
    hooks:
      - id: gixy
        files: \.conf$
```

## 严重级别映射

Gixy 严重级别映射到 Checkstyle 严重级别如下：

| Gixy 严重级别 | Checkstyle 严重级别 |
|---------------|---------------------|
| HIGH | error |
| MEDIUM | warning |
| LOW | info |
| UNSPECIFIED | info |

根据需要配置您的 CI/CD 工具在特定严重级别时中断构建。

--8<-- "zh/snippets/amplify-cta.md"
