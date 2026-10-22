---
title: "Интеграция с CI/CD"
description: "Интегрируйте Gixy в ваш CI/CD конвейер для автоматического сканирования конфигураций NGINX на наличие проблем безопасности. Поддержка Jenkins, GitLab CI, GitHub Actions и других систем."
---

# Интеграция с CI/CD

Gixy легко интегрируется с CI/CD конвейерами для обнаружения ошибок конфигурации безопасности NGINX до того, как они попадут в продакшен.

## Вывод в формате Checkstyle XML

Для интеграции с CI/CD используйте опцию `--format checkstyle` для генерации машиночитаемого XML-вывода:

```bash
gixy --format checkstyle /etc/nginx/nginx.conf > gixy-report.xml
```

Формат Checkstyle XML — это широко поддерживаемый стандарт для инструментов статического анализа, нативно поддерживаемый:

- **Jenkins** (плагин Warnings Next Generation)
- **GitLab CI** (отчёты Code Quality)
- **GitHub Actions** (через reviewdog, super-linter)
- **Bitbucket Pipelines** (Code Insights)
- **SonarQube** (импорт внешних проблем)
- **Многими IDE** (IntelliJ, Eclipse, VS Code)

### Пример вывода

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

### С использованием reviewdog

Для встроенных комментариев в PR используйте [reviewdog](https://github.com/reviewdog/reviewdog):

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

С использованием [плагина Warnings Next Generation](https://plugins.jenkins.io/warnings-ng/):

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

Для контейнеризованных конвейеров:

```bash
docker run --rm -v /path/to/nginx:/etc/nginx:ro \
  getpagespeed/gixy --format checkstyle /etc/nginx/nginx.conf
```

## Коды выхода

Gixy использует коды выхода для указания результатов сканирования:

| Код выхода | Значение |
|-----------|---------|
| 0 | Проблем не найдено |
| 1 | Найдены проблемы |
| 2 | Ошибка конфигурации |

Используйте их в вашем CI/CD конвейере для прерывания сборки при обнаружении проблем безопасности:

```bash
gixy /etc/nginx/nginx.conf || exit 1
```

## Pre-commit хук

Добавьте Gixy в вашу конфигурацию pre-commit:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/dvershinin/gixy
    rev: v0.2.24
    hooks:
      - id: gixy
        files: \.conf$
```

## Соответствие уровней серьёзности

Уровни серьёзности Gixy соответствуют уровням Checkstyle следующим образом:

| Серьёзность Gixy | Серьёзность Checkstyle |
|---------------|---------------------|
| HIGH | error |
| MEDIUM | warning |
| LOW | info |
| UNSPECIFIED | info |

Настройте ваш CI/CD инструмент для прерывания сборки при определённых уровнях серьёзности по необходимости.

--8<-- "ru/snippets/amplify-cta.md"
