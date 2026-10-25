---
title: "变量与分层 Drop-in"
description: "通过可信的分层策略文件描述第三方 NGINX 变量值。"
---

# 变量与 Drop-in

Gixy 内置 NGINX 变量模型，包括第三方变量的精确名称 `$brotli_ratio`。
保守模型 `[0-9.]*` 描述十进制输出或空值，排除 CR/LF 和 `/`，同时保留点号以维持
保守的 SSRF 检测。依据是
[ngx_brotli v0.1.4 getter](https://github.com/GetPageSpeed/ngx_brotli/blob/v0.1.4/filter/ngx_http_brotli_filter_module.c#L778-L816)。
模型描述可能的值，不证明目标模块已安装或加载。没有将整个 `brotli_` 前缀标为安全；
未知变量仍会产生诊断信息。

## 模块变量与配置声明

> **尚未发布（main 分支，下个版本）：** 本节描述 0.2.58 之后的变更。
> 下文的分层目录功能已在 0.2.58 中提供。

内置模型涵盖压缩率、srcache、Echo、VTS 计数器、精确的 GeoIP/SSL 名称，
以及已记录的 JWT claims/headers。模型只描述可能字符，不代表模块已安装。
数据库、证书、JWT 和脚本的不透明输出仍保留安全检查。
`$ssl_typo`、`$geoip_typo`、`$jwt_type` 等未支持名称仍为未知。
参见[源码固定版本覆盖矩阵](../en/module-variable-coverage.md)。

GeoIP2 可在 `http` 或 `stream` 主上下文直接声明任意别名。
`default=US` 或 `country iso_code` 路径不能证明输出安全：数据库可能返回任意字节。
默认值按字面量处理，不展开变量。仅精确的 `metadata build_epoch`、
`metadata last_check`、`metadata last_change` 使用十进制字符界限。
Gixy 不打开数据库，也不执行 `source=` 表达式。

本地名称不区分大小写。外部 include 展开后，最后一个 GeoIP2 声明在整个主上下文
生效，包括声明之前的使用位置。GeoIP2 内部的 include 无效，会在读取文件或展开
转储之前跳过。HTTP/stream 上下文及不同审计彼此隔离；禁用系统策略加载时配置
声明仍优先于目录模型。与 map/geo/njs/Perl 目标重名时采用不透明模型，并报告全部
声明位置。局部 `set` 保留原有覆盖行为。

`set_by_lua`、`set_by_lua_file`、`set_by_lua_block`、`perl_set`、`js_set`、
`js_var` 的输出均不透明。不执行脚本或读取脚本文件；可写 `js_var` 的初值不是
永久安全界限。配置定义的动态代理主机需要 resolver，除非能够证明是字面量 IP
或 upstream；不会把正则表达式当作主机名。


## 层级与优先级

普通 CLI（包括无参数及 stdin 扫描）按以下顺序加载，越靠后优先级越高：

1. 内置模型。
2. `/usr/share/gixy/vars.d` 中的供应商/模块定义。
3. `/etc/gixy/vars.d` 中的管理员定义。
4. `--vars-dirs` 显式目录，按提供顺序加载，后面的目录优先。

每个目录是独立层。`.cfg` 和 `.conf` 文件按文件名字典序读取；同一键最后一个有效
定义生效，同一文件中的重复定义也如此。无效条目会显示文件及行号警告，并保留此前
或较低层的有效定义。

首先选中含有匹配项的最高层，再选精确名称，否则选择最长的 `_` 结尾匹配前缀。
因此高层的 `http_` 可覆盖低层的 `http_host`。同层中精确名称高于前缀；对
`$http_special_value`，`http_special_` 高于 `http_`。这修正了以前依赖插入顺序的
前缀匹配歧义。被分析 NGINX 配置中定义的变量仍优先于模型目录。

## 控制与隔离

```sh
gixy --vars-dirs /etc/gixy/vars,~/.config/gixy/vars
```

```cfg
# 逗号分隔的标量文本，不要加方括号
vars-dirs = /etc/gixy/vars, ~/.config/gixy/vars
load-default-vars = false
```

`--no-default-vars` 关闭系统目录，保留内置及显式目录；`--load-default-vars` 开启
系统目录。两个相反标志不能同时使用。规范配置键为 `load-default-vars`，环境变量为
`GIXY_LOAD_DEFAULT_VARS=true` 或 `false`。优先级：CLI > 环境 > 配置 > 模式默认值。
显式 `false` 不会丢失；`--write-config` 以规范布尔键保存该选择。显式目录始终高于
启用的系统层。旧的 `/etc/gixy/vars` 和 `~/.config/gixy/vars` 仍可显式选用，但不会
自动搜索。

库 `Config(load_default_vars=False)` 和 `--server` 默认仅使用内置模型。操作员可在
启动时开启系统目录或传入 `vars_dirs`。单个服务器请求及上传的 NGINX 文本无法更改
策略或选择策略路径。每次审计都会创建新目录并与本次子上下文共享，避免自定义模型
跨审计泄漏。分析器仍有其他全局状态，因此不保证整体线程安全。

## 文件格式与信任

每行可为 `name value`、`name = value` 或 `name: value`。名称为 ASCII 标识符，不含
`$`；以 `_` 结尾表示前缀。数字捕获变量不属于模型目录。忽略空行及 `#`/`;` 注释。

```cfg
foo_host "example.com"
foo_literal 'a.b[$http_host]'
foo_uri r'/[^\s]*',
legacy_uri /[^\s]*
operator_asserted_safe none
```

普通引号表示字面值，不进行变量插值、Python 转义解析或求值。`r'...'`/`r"..."` 表示
正则；兼容旧的无引号正则。仅静态检查正则语法，绝不将提供的正则用于字符串匹配。
允许尾随逗号。`none`、`null`（不区分大小写）、`''`、`""` 是明确的可信断言，表示
值不受用户控制。这些断言可抑制安全发现，使用前应有依据。缺值、引号未闭合、名称
错误及正则语法错误会被拒绝并警告，不会变成安全断言。

自动系统策略要求所有祖先目录、策略目录及普通定义文件均归 root 所有，且组和其他
用户不可写。拒绝符号链接，包括祖先路径中的链接。支持的 POSIX 平台使用持有的
no-follow 文件描述符防止路径竞争；无法安全加载的平台会警告并跳过系统策略。
可选目录不存在时不报错，扫描不会创建目录。

显式路径是操作员的可信选择，支持 `~`，非 root 用户也可使用。缺失、不可读或无效的
显式文件会警告。不会隐式搜索当前目录或用户目录。模块 RPM 可提供 root:root/0644
普通供应商数据而无需依赖 Gixy；共享供应商目录属性为 root:root/0755。管理员覆盖
放在 `/etc/gixy/vars.d`。移除模块定义后回退至内置模型。策略仅影响分析，不改变
NGINX 行为或模块启用状态。
