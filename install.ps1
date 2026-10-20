param(
    [ValidateSet('auto','codex','opencode','both','none')][string]$Client = 'auto',
    [string]$Python = 'python',
    [string]$InstallDir = '',
    [string]$CodexHome = '',
    [string]$OpenCodeConfig = '',
    [int]$Port = 8791
)
$ErrorActionPreference = 'Stop'
& $Python -c "import sys; assert sys.version_info >= (3,10), 'Python 3.10+ required'"
if ($LASTEXITCODE -ne 0) { throw '请使用已安装的 Python 3.10 或以上，可用 -Python 指定路径。' }
$taskArgs = @((Join-Path $PSScriptRoot 'deploy.py'),'install','--client',$Client,'--port',"$Port")
if ($InstallDir) { $taskArgs += @('--install-dir',$InstallDir) }
if ($CodexHome) { $taskArgs += @('--codex-home',$CodexHome) }
if ($OpenCodeConfig) { $taskArgs += @('--opencode-config',$OpenCodeConfig) }
& $Python -X utf8 @taskArgs
if ($LASTEXITCODE -ne 0) { throw '自动安装部署未完成；查看上一条脱敏错误并按 SKILL.md 处理。' }
