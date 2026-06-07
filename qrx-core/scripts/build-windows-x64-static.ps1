param(
    [string]$VcpkgRoot = "C:\vcpkg",
    [string]$BuildDir = "build-windows-x64-static"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")

if (!(Test-Path $VcpkgRoot)) {
    git clone https://github.com/microsoft/vcpkg $VcpkgRoot
    & "$VcpkgRoot\bootstrap-vcpkg.bat"
}

& "$VcpkgRoot\vcpkg.exe" install openssl:x64-windows-static

$BuildPath = Join-Path $Root $BuildDir
if (Test-Path $BuildPath) { Remove-Item -Recurse -Force $BuildPath }
New-Item -ItemType Directory -Path $BuildPath | Out-Null
Set-Location $BuildPath

cmake $Root `
  -G "Visual Studio 17 2022" `
  -A x64 `
  -DCMAKE_TOOLCHAIN_FILE="$VcpkgRoot\scripts\buildsystems\vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static `
  -DOPENSSL_USE_STATIC_LIBS=TRUE `
  -DQRX_REQUIRE_PQC=ON

cmake --build . --config Release

Write-Host "Built Windows x64 static QRX binaries in $BuildPath\Release"
Write-Host "Check dependencies with: dumpbin /DEPENDENTS .\Release\qrxd.exe"
