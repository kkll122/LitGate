---
name: litgate
description: Install and deploy LitGate to the current Codex or OpenCode client from a secret-free package with one instruction; also configure credentials and perform multi-source literature searches. Use for LitGate installation, MCP connection, startup verification, search, or safe redistribution.
---

# LitGate：一句话自动安装与部署

用户可将完整安装包放在代理可访问的本地目录，发送：

> 请读取 LitGate 安装包中的 SKILL.md，自动安装并部署到当前客户端，完成验证后告诉我使用入口。

安装请求授权以下本机工作：创建独立运行目录和环境、下载所需依赖、生成自己的本机凭据、后台启动网关、只更新当前客户端的 LitGate MCP 配置、验证连接。只有用户要求两端时才同时注册 Codex 和 OpenCode。搜索或使用请求不自动修改客户端配置。

## 给安装代理的执行流程

1. 定位或解压用户提供的包；确认以下八个文件同处 `litgate` 文件夹：`SKILL.md`、`litgate.py`、`search_core.py`、`mcp_client.py`、`deploy.py`、`requirements.txt`、`install.ps1`、`register-mcp.ps1`。不要从原安装复制数据库、凭据、缓存或虚拟环境。
2. 使用本机已有 Python 3.10+；若默认 `python` 不可用，检查已安装的 Python 或启动器并传入实际可执行路径。不要为此替换系统 Python。确定正在执行任务的客户端：Codex 选 `codex`，OpenCode 选 `opencode`；不要因为两者均已安装就默认修改两者。
3. Windows 在包目录执行对应命令之一：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Client codex
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Client opencode
```

`Bypass` 仅用于本次进程，不更改系统执行策略。指定已有 Python 路径用 `-Python "C:\路径\python.exe"`。安装器自动复制白名单源码到稳定目录，在该目录创建 `.venv` 并安装依赖，无须先手动设置密码或生成客户端密钥。

macOS/Linux 使用相同 Python 安装器：

```sh
python3 deploy.py install --client codex
# 在 OpenCode 中将 codex 改为 opencode
```

4. 检查最终 JSON 中 `ok=true`、`verification.health=true`、`client_auth=true`，以及 MCP `handshake=true`、`tools=3`、`authenticated_quota=true`。安装器打印路径和状态，不打印密码或密钥。失败时依照脱敏错误修复实际问题，不能声称已完成；配置无效或系统权限被拒时不重写无关设置或绕过权限。
5. 当前客户端支持刷新 MCP 时刷新该连接，再确认 LitGate 的三个工具已出现；否则明确告知用户重启一次客户端或开启新会话。不要退出或中断当前任务以强制重启。报告安装目录、管理页面实际地址、私有密码文件位置和验证结果，不输出该文件内容。

不为常规安装选择反复询问用户。上游平台账户登录或密钥申请仅在用户主动需要该平台时进行，不影响默认无密钥检索。

## 自动完成的部署内容

- 默认 Windows 目录：`%LOCALAPPDATA%\LitGate\auto`；macOS：`~/Library/Application Support/LitGate/auto`；Linux：`$XDG_DATA_HOME/litgate/auto` 或 `~/.local/share/litgate/auto`。
- `app` 存八文件源码及独立 `.venv`；`data` 存本机数据库、随机管理密码文件 `admin-password.txt`、随机客户端密钥文件 `client.key`、运行状态与日志。Windows 权限限制为当前用户、SYSTEM、管理员；Unix 私有目录为 700、文件为 600。
- 管理密码与客户端密钥在安装机生成，数据库只保存两者哈希；其原文在私有目录。上游密钥未随包提供、不会复制他人的密钥。用户需要登录网页时自行打开密码文件查看；代理只报告位置。
- 初始启用 Crossref、OpenAlex、arXiv，支持无密钥检索。Semantic Scholar、Scopus、DBLP 可在管理页另行配置和启用。
- 默认只监听 `127.0.0.1:8791`；已被其他服务占用时在后续最多100个端口中选择空闲端口，实际地址以安装结果为准，不停止其他服务。
- Codex 配置使用 `[mcp_servers.litgate]`；OpenCode 使用 `mcp.litgate` 本地服务。仅更改 LitGate 条目，保留其他配置值；修改前把精确原文备份到私有 `data/config-backups`。Codex TOML 保留注释；OpenCode JSONC 可重新排版为合法 JSON，原始注释保留在备份中。
- MCP 命令是独立环境 Python 调用 `deploy.py mcp`；启动和每次工具请求都检查并自动拉起本安装的网关，因此电脑重启或连接切换后再次调用可自动恢复。不会创建系统服务或计划任务。
- 重复执行不会重置已有管理密码、替换已有效的客户端密钥、删除上游配置或重复拉起网关。已撤销的客户端密钥不会被静默恢复。

## 参数与运行管理

Windows 可指定 `-InstallDir`、`-CodexHome`、`-OpenCodeConfig`、`-Port`。`-Client both` 仅在用户要求两端时使用；`-Client none` 仅安装网关和验证，不改客户端。`auto` 优先识别 Codex 任务环境或唯一可用客户端；仍有歧义时代理应根据自身任务环境显式传参。

Python 对应参数为 `--install-dir`、`--codex-home`、`--opencode-config`、`--port`。遵循已配置的 `CODEX_HOME` 和 `OPENCODE_CONFIG`；OpenCode 全局目录同存 JSON 与 JSONC 时仅在两文件同步该服务条目，避免优先级歧义。代理发现当前项目或受管理配置覆盖了此服务时，应报告并处理用户授权范围内的 LitGate 条目，不能覆盖机构策略。

安装后，在安装目录使用自己的独立环境 Python 和 `app/deploy.py`：

```text
deploy.py status --install-dir <安装目录>   # 查询地址和运行状态
deploy.py verify --install-dir <安装目录>   # 检查并按需启动，验证鉴权与MCP
deploy.py stop --install-dir <安装目录>     # 仅停止路径和PID都核对为本安装的网关
```

`register-mcp.ps1 -Client codex/opencode` 可在已安装后重新注册；可选的 Claude 接入用 `-Client claude -ConfigPath <配置JSON路径>`，也使用自动安装的私有凭据。上述 Windows 脚本不适用于其他系统。

前置条件是已有 Python 3.10+、可联网下载依赖及写入本机安装和客户端配置的权限。系统需要批准权限时按当前代理的正常流程申请，不声称能免除系统审批。现有客户端可能需要刷新或重启一次才能加载新增工具。

Codex 配置依据：[官方 MCP 文档](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)。OpenCode 配置依据：[官方 MCP 文档](https://opencode.ai/docs/mcp-servers/)、[配置文档](https://opencode.ai/docs/config/)。核验日期：2026-10-08。

## 密钥申请与查询入口

上游密钥用于文献平台；`lg_…` 密钥用于自己的本机网关。官方入口核验日期为2026-10-08，核验了文档、入口或登录跳转，未登录个人账户或测试原项目真实密钥。

| 数据源 | 入口 | 条件 |
|---|---|---|
| OpenAlex | [申请 / 查询 / 轮换](https://openalex.org/settings/api)、[认证说明](https://help.openalex.org/api/authentication/) | 官方文档指定设置入口，账户页需登录与JavaScript；无密钥可受限检索。 |
| Semantic Scholar | [官方申请页](https://webflow.semanticscholar.org/product/api)、[接口文档](https://api.semanticscholar.org/api-docs/) | 点击Request an API Key，邮件接收密钥；规范域名核验时403，使用可访问的官方页面。 |
| Scopus | [Elsevier 密钥管理](https://dev.elsevier.com/apikey/manage)、[接口文档](https://dev.elsevier.com/documentation/SCOPUSSearchAPI.wadl) | 入口跳转Elsevier登录；部分权限需要机构网络或向机构索取InstToken。 |
| Crossref | [API说明](https://www.crossref.org/documentation/retrieve-metadata/rest-api/) | 无需密钥，可选联系邮箱。 |
| arXiv | [API手册](https://info.arxiv.org/help/api/user-manual.html) | 无需密钥，约三秒请求间隔。 |
| DBLP | [官方检索](https://dblp.org/search) | 无API密钥；可能出现浏览器验证，Cookie不保证恢复API访问。 |

在「管理 → 端点 → 配置」填写自己的上游凭据；窗口也显示这些入口和核验说明。已保存的密钥不回传到浏览器，留空保存保留原值，清除并保存才删除。新输入凭据在本次表单保存前会出现在表单中；浏览器不保存密钥历史。

## 本机自主转发与自动拉起（2026-10-13 用户持久约定）

LitGate 是用户本机的自主文献转发服务。用户要求使用 LitGate 检索时，已授权按需启动现有本机网关，无需再次询问“是否启动”。先恢复网关再检索，不把连接拒绝直接当作平台不可用，也不优先绕过网关直接调用上游。

1. 先检查当前安装的 `/healthz`。已健康则复用；连接拒绝且确认现有实例未运行时启动一次，再核验。健康但 `powered=false` 表示总闸关闭，不能当作进程离线绕过。
2. 自动部署安装优先沿用 `deploy.py mcp` 的按需恢复，或运行 `deploy.py verify --install-dir <已有安装目录>`。旧版源码部署则使用已核验 Python 和该目录 `litgate.py`，显式指定原数据库、`--host 127.0.0.1 --port <原端口> --no-browser`；Windows 后台启动使用 `Start-Process -WindowStyle Hidden`。
3. 保留原数据库、凭据、上游配置和客户端配置。端口已占用时先核验进程身份；不重复启动，不按端口杀进程，不自动重装或重置。既有实例故障且一次拉起仍失败时记录具体原因，继续可完成的研究工作。
4. 启动后核验程序/数据库路径及监听身份、`/healthz`、主页；再验证现有鉴权检索或 MCP。分别报告“网关在线”“鉴权可用”“上游查询成功”，不能以健康检查代替完整检索验证。需要权限时使用执行环境的正常审批机制。

此约定授权的是现有 LitGate 文献转发进程的按需启动，不扩展为重启/加载其他模型服务的授权。

## 使用文献检索

工具：`litgate_search`、`litgate_quota`、`litgate_usage`。网页勾选来源，或工具用 `source=all` / 逗号分隔的来源。`limit=1–50` 为每源取回量。

- `field=all/title/abstract/author`；Crossref无摘要检索，Semantic Scholar无作者检索，DBLP无摘要检索；不支持时明确跳过。Semantic Scholar标题/摘要、DBLP标题/作者在返回批次筛选。
- `year_from/year_to`、`cited_min/cited_max` 包含端点；`venue/author` 是返回元数据包含匹配，`exclude` 用英文逗号分隔，`oa=any/yes`，`dedupe` 布尔。
- `sort=relevance/newest/oldest/cited/cited_asc`。去重优先规范化DOI，其次长标题、年份、首位作者；不同DOI不按同题名强制合并。

仅对本次取回批次合并、筛选、排序，数量不是全库命中数。相关度融合各源返回排名。引用量缺失不是零；设置引用量范围排除未知值。不同来源计数不相加；合并记录优先OpenAlex、Scopus、Semantic Scholar、Crossref，并保留逐源值。作者只取前六位，包含筛选可能遗漏后列作者。只保留明确标为开放获取的记录，不把未知视为开放。

Google Scholar不在接入源列表中。上游失败保留其他成功来源并披露原因；一次空结果不能证明文献不存在。本机配额工具查询客户端频率配额，上游额度到官方账户页查询。

## 保持分发包无密钥

再分发只使用上述八文件白名单。排除 `data`、`*.db`、`.venv`、缓存、字节码、日志、客户端配置、凭据文件与配置备份；不要整目录打包已经运行过的安装。上游凭据配置后仍会存于本机数据库，数据库是私有运行数据。

ZIP只含源码、脚本和本指导，不含依赖；不能离线安装。安装到新的电脑会生成新的本机凭据，绝不复用发布者的密码或密钥。
