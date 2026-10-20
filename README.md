# LitGate 文献网关

LitGate 将多个文献来源汇集为本机网页和 MCP 工具，可供 Codex、OpenCode 使用。

## 一句话自动安装

下载 [最小安装包](dist/LitGate.zip)，解压后交给当前客户端：

> 请读取 LitGate 安装包中的 SKILL.md，自动安装并部署到当前客户端，完成验证后告诉我使用入口。

也可克隆本仓库，然后让客户端读取根目录的 [SKILL.md](SKILL.md) 执行安装。

需要已有 Python 3.10+、联网下载依赖及本机写入权限。安装器创建独立环境与本机凭据，启动网关，注册当前客户端并验证；客户端可能需要刷新 MCP 或重启一次。

Windows 手动安装：

```powershell
.\install.ps1 -Client codex
# OpenCode 使用 -Client opencode
```

macOS / Linux 安装入口（尚未在这两类系统实机验证）：

```sh
python3 deploy.py install --client codex
```

## 检索功能

- 接入 Crossref、OpenAlex、Semantic Scholar、Scopus、arXiv、DBLP；默认启用 Crossref、OpenAlex、arXiv，其他来源按需配置。
- 支持来源选择、标题/摘要/作者检索、年份、引用量、期刊、作者、排除词、开放获取筛选，以及相关度、年份、引用量排序与去重。
- 筛选和排序作用于本次取回的结果，不代表全库穷尽检索；不同来源的功能、授权和额度各有差异。
- 返回可用的公开全文链接；当前版本没有自动下载 PDF 的工具。Scopus 检索密钥不代表取得全文下载权限。

MCP 工具：`litgate_search`、`litgate_quota`、`litgate_usage`。密钥申请入口、配置与运行管理见 [SKILL.md](SKILL.md)。

## 凭据与分发

本仓库和 ZIP 不附带上游密钥、管理密码、客户端密钥、数据库、缓存或个人检索记录。每次新安装在私有运行目录生成本机凭据。上游密钥由使用者自行申请并配置。

安装后产生的数据库可能包含上游凭据，必须留在私有运行目录。发布仅使用安装包规定的八文件白名单，不能整体上传已经运行过的安装目录。`.gitignore` 提供额外排除规则。

Windows 安装、重复安装、独立客户端配置和 MCP 连接已在隔离环境验证；本次发布复核核心代码与该验证版本一致，仅更新安装文档。包内不含依赖，无法离线安装。
