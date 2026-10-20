param(
    [ValidateSet('auto','codex','opencode','both','claude')][string]$Client = 'auto',
    [string]$InstallDir = '',
    [string]$CodexHome = '',
    [string]$OpenCodeConfig = '',
    [string]$ConfigPath = ''
)
$ErrorActionPreference = 'Stop'
$taskRoot = if ($InstallDir) { $InstallDir } else { Join-Path $env:LOCALAPPDATA 'LitGate\auto' }
$taskExe = Join-Path $taskRoot 'app\.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $taskExe)) { throw '请先运行 install.ps1。' }
$taskArgs = @((Join-Path $taskRoot 'app\deploy.py'),'finish','--install-dir',$taskRoot,'--client',$Client)
if ($CodexHome) { $taskArgs += @('--codex-home',$CodexHome) }
if ($Client -eq 'claude') {
    if (-not $ConfigPath) { throw 'Claude 接入请显式指定 -ConfigPath。' }
    $taskArgs += @('--opencode-config',$ConfigPath)
} elseif ($OpenCodeConfig) { $taskArgs += @('--opencode-config',$OpenCodeConfig) }
& $taskExe @taskArgs
if ($LASTEXITCODE -ne 0) { throw 'MCP注册或验证失败；已有其他配置保留。' }
