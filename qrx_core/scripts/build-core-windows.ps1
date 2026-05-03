
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Set-Location "$PSScriptRoot\..\vendor\qrx-core"
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
Write-Host "Built QRX core in vendor/qrx-core/build"
