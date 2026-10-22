---
title: "CI/CD Integration"
description: "Integrate Gixy into your CI/CD pipeline to automatically scan NGINX configs for security issues. Supports Jenkins, GitLab CI, GitHub Actions, and more."
---

# CI/CD Integration

Gixy integrates seamlessly with CI/CD pipelines to catch NGINX security misconfigurations before they reach production.

## Checkstyle XML Output

For CI/CD integration, use the `--format checkstyle` option to generate machine-readable XML output:

```bash
gixy --format checkstyle /etc/nginx/nginx.conf > gixy-report.xml
```

The Checkstyle XML format is a widely-supported standard for static analysis tools, natively consumed by:

- **Jenkins** (Warnings Next Generation plugin)
- **GitLab CI** (Code Quality reports)
- **GitHub Actions** (via reviewdog, super-linter)
- **Bitbucket Pipelines** (Code Insights)
- **SonarQube** (External issues import)
- **Many IDEs** (IntelliJ, Eclipse, VS Code)

### Example Output

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

### With reviewdog

For inline PR comments, use [reviewdog](https://github.com/reviewdog/reviewdog):

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

Using the [Warnings Next Generation Plugin](https://plugins.jenkins.io/warnings-ng/):

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

For containerized pipelines:

```bash
docker run --rm -v /path/to/nginx:/etc/nginx:ro \
  getpagespeed/gixy --format checkstyle /etc/nginx/nginx.conf
```

## Exit Codes

Gixy uses exit codes to indicate scan results:

| Exit Code | Meaning |
|-----------|---------|
| 0 | No issues found |
| 1 | Issues found |
| 2 | Configuration error |

Use these in your CI/CD pipeline to fail builds on security issues:

```bash
gixy /etc/nginx/nginx.conf || exit 1
```

## Pre-commit Hook

Add Gixy to your pre-commit configuration:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/dvershinin/gixy
    rev: v0.2.24
    hooks:
      - id: gixy
        files: \.conf$
```

## Severity Mapping

Gixy severities map to Checkstyle severities as follows:

| Gixy Severity | Checkstyle Severity |
|---------------|---------------------|
| HIGH | error |
| MEDIUM | warning |
| LOW | info |
| UNSPECIFIED | info |

Configure your CI/CD tool to fail on specific severity levels as needed.

--8<-- "en/snippets/amplify-cta.md"
