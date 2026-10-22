---
title: "IDE 集成"
description: "在您的 IDE 中直接使用 Gixy，通过 Visual Studio Code 扩展进行实时 NGINX 安全分析。"
---

# IDE 集成

直接在编辑器中获取实时 NGINX 安全反馈。

## Visual Studio Code

[vscode-gixy](https://github.com/dvershinin/vscode-gixy) 扩展将 Gixy 的安全分析直接集成到 VS Code 中。

### 功能

- **实时扫描** — 编辑 NGINX 配置文件时自动分析
- **内联诊断** — 安全问题直接在编辑器中高亮显示
- **快速修复** — 针对常见问题的建议修复
- **悬停信息** — 悬停在问题上时显示详细说明
- **Problems 面板集成** — 所有问题都显示在 VS Code 的 Problems 面板中

### 安装

1. 打开 VS Code
2. 转到 Extensions（Ctrl+Shift+X / Cmd+Shift+X）
3. 搜索 "gixy"
4. 点击 Install

或从命令行安装：

```bash
code --install-extension dvershinin.vscode-gixy
```

### 要求

扩展需要安装 Gixy：

```bash
pip install gixy-ng
```

### 配置

在 VS Code 设置中配置扩展：

```json
{
  "gixy.executable": "gixy",
  "gixy.runOnSave": true,
  "gixy.runOnOpen": true
}
```

### 截图

问题以严重级别指示器内联显示：

- 🔴 **Error** — 高严重级别安全问题
- 🟡 **Warning** — 中等严重级别问题
- 🔵 **Info** — 低严重级别建议

点击任何问题以查看详细信息和文档链接。

## 其他编辑器

### JetBrains IDE（IntelliJ、PyCharm、WebStorm）

使用 [Checkstyle-IDEA 插件](https://plugins.jetbrains.com/plugin/1065-checkstyle-idea) 配合 Gixy 的 checkstyle 输出：

1. 运行 `gixy --format checkstyle nginx.conf > gixy-report.xml`
2. 在 Checkstyle 插件中导入报告

### Vim/Neovim

使用 [ALE](https://github.com/dense-analysis/ale) 或 [nvim-lint](https://github.com/mfussenegger/nvim-lint) 配合自定义 linter 配置：

```vim
" ALE 的 Gixy 配置
let g:ale_linters = {
\   'nginx': ['gixy'],
\}
```

### Sublime Text

使用 [SublimeLinter](https://github.com/SublimeLinter/SublimeLinter) 配合自定义 linter 插件，或通过构建系统运行 Gixy：

```json
{
    "cmd": ["gixy", "$file"],
    "selector": "source.nginx"
}
```

## 终端集成

### 点击跳转

Gixy 的富终端输出以终端兼容格式显示文件位置：

```
📍 /etc/nginx/nginx.conf:42
```

大多数现代终端（iTerm2、Windows Terminal、VS Code 集成终端）支持点击这些路径直接跳转到文件和行。

--8<-- "zh/snippets/amplify-cta.md"
