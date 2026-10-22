---
title: "IDE Integration"
description: "Use Gixy directly in your IDE — JetBrains plugin or VS Code extension — for real-time NGINX security analysis."
---

# IDE Integration

Get real-time NGINX security feedback directly in your editor.

## JetBrains IDEs (IntelliJ, PyCharm, WebStorm, GoLand, …)

The [gixy-jetbrains](https://github.com/GetPageSpeed/gixy-jetbrains) plugin brings Gixy's security analysis to all JetBrains IDEs. **No Python installation required** — the plugin automatically downloads a native Gixy binary for your platform.

[![JetBrains Plugin](https://img.shields.io/jetbrains/plugin/v/30510-gixy?label=JetBrains%20Marketplace&logo=jetbrains&style=flat-square)](https://plugins.jetbrains.com/plugin/30510-gixy)

### Features

- **Zero setup** — auto-downloads a platform-specific Gixy binary; no Python needed
- **Real-time scanning** — automatic analysis as you edit NGINX config files
- **Inline diagnostics** — security issues highlighted directly in the editor with severity markers
- **Quick fixes** — one-click remediation for supported issues
- **Problem panel integration** — all issues listed in the IDE's Inspections/Problems panel

### Installation

1. Open your JetBrains IDE
2. Go to **Settings → Plugins → Marketplace**
3. Search for **"Gixy"**
4. Click **Install** and restart the IDE

Or install directly from [JetBrains Marketplace](https://plugins.jetbrains.com/plugin/30510-gixy).

### Configuration

Configure the plugin in **Settings → Tools → Gixy**:

| Setting | Default | Description |
|---------|---------|-------------|
| Gixy executable | *(auto-downloaded)* | Path to the Gixy binary. Leave blank to use the bundled binary. |
| Run on save | `true` | Analyse files automatically when saved |
| Run on open | `true` | Analyse files when first opened |
| Severity mapping | *(built-in)* | Maps Gixy severity levels to IDE inspection severities |

## Visual Studio Code

The [vscode-gixy](https://github.com/dvershinin/vscode-gixy) extension brings Gixy's security analysis directly into VS Code.

### Features

- **Real-time scanning** - Automatic analysis as you edit NGINX config files
- **Inline diagnostics** - Security issues highlighted directly in the editor
- **Quick fixes** - Suggested remediation for common issues
- **Hover information** - Detailed explanations when hovering over issues
- **Problem panel integration** - All issues listed in VS Code's Problems panel

### Installation

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X / Cmd+Shift+X)
3. Search for "gixy"
4. Click Install

Or install from the command line:

```bash
code --install-extension dvershinin.vscode-gixy
```

### Requirements

The extension requires Gixy to be installed:

```bash
pip install gixy-ng
```

### Configuration

Configure the extension in VS Code settings:

```json
{
  "gixy.executable": "gixy",
  "gixy.runOnSave": true,
  "gixy.runOnOpen": true
}
```

### Screenshots

Issues are displayed inline with severity indicators:

- 🔴 **Error** - High severity security issues
- 🟡 **Warning** - Medium severity issues
- 🔵 **Info** - Low severity recommendations

Click on any issue to see detailed information and documentation links.

## Other Editors

### Vim/Neovim

Use [ALE](https://github.com/dense-analysis/ale) or [nvim-lint](https://github.com/mfussenegger/nvim-lint) with a custom linter configuration:

```vim
" ALE configuration for Gixy
let g:ale_linters = {
\   'nginx': ['gixy'],
\}
```

### Sublime Text

Use [SublimeLinter](https://github.com/SublimeLinter/SublimeLinter) with a custom linter plugin, or run Gixy from the build system:

```json
{
    "cmd": ["gixy", "$file"],
    "selector": "source.nginx"
}
```

## Terminal Integration

### Click-to-Jump

Gixy's rich console output formats file locations in a terminal-compatible format:

```
📍 /etc/nginx/nginx.conf:42
```

Most modern terminals (iTerm2, Windows Terminal, VS Code integrated terminal) support clicking these paths to jump directly to the file and line.

--8<-- "en/snippets/amplify-cta.md"
