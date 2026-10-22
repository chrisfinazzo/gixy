---
title: "Интеграция с IDE"
description: "Используйте Gixy прямо в вашей IDE с расширением Visual Studio Code для анализа безопасности NGINX в реальном времени."
---

# Интеграция с IDE

Получайте обратную связь по безопасности NGINX в реальном времени прямо в вашем редакторе.

## Visual Studio Code

Расширение [vscode-gixy](https://github.com/dvershinin/vscode-gixy) интегрирует анализ безопасности Gixy непосредственно в VS Code.

### Возможности

- **Сканирование в реальном времени** — Автоматический анализ при редактировании файлов конфигурации NGINX
- **Встроенная диагностика** — Проблемы безопасности подсвечиваются прямо в редакторе
- **Быстрые исправления** — Предложения по устранению типичных проблем
- **Информация при наведении** — Подробные объяснения при наведении курсора на проблемы
- **Интеграция с панелью Problems** — Все проблемы отображаются в панели Problems VS Code

### Установка

1. Откройте VS Code
2. Перейдите в Extensions (Ctrl+Shift+X / Cmd+Shift+X)
3. Найдите "gixy"
4. Нажмите Install

Или установите из командной строки:

```bash
code --install-extension dvershinin.vscode-gixy
```

### Требования

Для работы расширения требуется установленный Gixy:

```bash
pip install gixy-ng
```

### Настройка

Настройте расширение в параметрах VS Code:

```json
{
  "gixy.executable": "gixy",
  "gixy.runOnSave": true,
  "gixy.runOnOpen": true
}
```

### Скриншоты

Проблемы отображаются встроенными с индикаторами серьёзности:

- 🔴 **Error** — Проблемы безопасности высокой серьёзности
- 🟡 **Warning** — Проблемы средней серьёзности
- 🔵 **Info** — Рекомендации низкой серьёзности

Нажмите на любую проблему для просмотра подробной информации и ссылок на документацию.

## Другие редакторы

### JetBrains IDE (IntelliJ, PyCharm, WebStorm)

Используйте [плагин Checkstyle-IDEA](https://plugins.jetbrains.com/plugin/1065-checkstyle-idea) с выводом Gixy в формате checkstyle:

1. Выполните `gixy --format checkstyle nginx.conf > gixy-report.xml`
2. Импортируйте отчёт в плагин Checkstyle

### Vim/Neovim

Используйте [ALE](https://github.com/dense-analysis/ale) или [nvim-lint](https://github.com/mfussenegger/nvim-lint) с пользовательской конфигурацией линтера:

```vim
" Конфигурация ALE для Gixy
let g:ale_linters = {
\   'nginx': ['gixy'],
\}
```

### Sublime Text

Используйте [SublimeLinter](https://github.com/SublimeLinter/SublimeLinter) с пользовательским плагином линтера или запускайте Gixy через систему сборки:

```json
{
    "cmd": ["gixy", "$file"],
    "selector": "source.nginx"
}
```

## Интеграция с терминалом

### Переход по клику

Расширенный консольный вывод Gixy форматирует пути к файлам в совместимом с терминалом формате:

```
📍 /etc/nginx/nginx.conf:42
```

Большинство современных терминалов (iTerm2, Windows Terminal, встроенный терминал VS Code) поддерживают клик по этим путям для прямого перехода к файлу и строке.

--8<-- "ru/snippets/amplify-cta.md"
