# Đặt PYTHONPATH để chạy các service và công cụ từ gốc repo (PowerShell).
# Dùng một lần cho mỗi terminal:  . .\scripts\env.ps1
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$paths = @(
    "common/core/src",
    "services/sensor/src",
    "services/honeypot/src",
    "services/redirector/src",
    "services/dashboard/src",
    "common"
) | ForEach-Object { Join-Path $root $_ }
$env:PYTHONPATH = $paths -join [IO.Path]::PathSeparator
Write-Host "PYTHONPATH đã được đặt cho $root"
