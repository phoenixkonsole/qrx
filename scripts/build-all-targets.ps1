param(
  [ValidateSet('host','linux-x64','linux-arm64','macos-x64','macos-arm64','windows-x64')]
  [string]$Target='host',
  [switch]$Plan,
  [switch]$InstallDependencies
)
$ErrorActionPreference='Stop'
$Repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path

# Non-Windows targets continue to use the audited POSIX orchestrator.
$OnWindows=($env:OS -eq 'Windows_NT')
if ($Target -ne 'windows-x64' -and -not ($Target -eq 'host' -and $OnWindows)) {
  $bash=Get-Command bash -ErrorAction SilentlyContinue
  if(-not $bash){ throw 'bash is required for non-Windows targets.' }
  $a=@((Join-Path $PSScriptRoot 'build-all-targets.sh'),'--target',$Target)
  if($Plan){$a+='--plan'}
  & $bash.Source @a; exit $LASTEXITCODE
}
$Target='windows-x64'

function Add-ProcessPath([string]$Dir) {
  if (-not $Dir -or -not (Test-Path $Dir)) { return }
  $parts=@($env:Path -split ';' | Where-Object { $_ })
  if ($parts -notcontains $Dir) { $env:Path="$Dir;$env:Path" }
}
function Refresh-ProcessPath {
  $machine=[Environment]::GetEnvironmentVariable('Path','Machine')
  $user=[Environment]::GetEnvironmentVariable('Path','User')
  $current=@($env:Path -split ';' | Where-Object { $_ })
  $merged=@()
  foreach($p in (@($machine -split ';') + @($user -split ';') + $current)) { if($p -and $merged -notcontains $p){$merged += $p} }
  $env:Path=($merged -join ';')
  Add-KnownToolPaths
}
function Add-KnownToolPaths {
  # Installers can update the persistent PATH without updating this running shell.
  # Add only well-known, existing native Windows tool locations.
  foreach($p in @(
    'C:\Strawberry\perl\bin','C:\Strawberry\c\bin',
    "$env:LOCALAPPDATA\Programs\Python\Python313", "$env:LOCALAPPDATA\Programs\Python\Python313\Scripts",
    "$env:USERPROFILE\.cargo\bin", 'C:\Program Files\CMake\bin', 'C:\Program Files\nodejs', 'C:\Program Files\Git\cmd', 'C:\Program Files\Git\bin'
  )) { Add-ProcessPath $p }
}
function Find-Python {
  # Return a single object instead of a PowerShell array. Returning an array from
  # a function is pipeline-unrolled; a one-element candidate then became a plain
  # string and $script:Python[0] evaluated to the first character (for example C).
  $candidates=@()
  $p=Get-Command python -ErrorAction SilentlyContinue
  if($p){$candidates += [pscustomobject]@{ Exe=$p.Source; Prefix=@() }}
  $py=Get-Command py -ErrorAction SilentlyContinue
  if($py){$candidates += [pscustomobject]@{ Exe=$py.Source; Prefix=@('-3') }}
  foreach($k in @("$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",'C:\Program Files\Python313\python.exe')){
    if(Test-Path $k){$candidates += [pscustomobject]@{ Exe=$k; Prefix=@() }}
  }
  foreach($c in $candidates){
    try {
      & $c.Exe @($c.Prefix) -c "import sys; assert sys.version_info >= (3,9)" 2>$null
      if($LASTEXITCODE -eq 0){return $c}
    } catch{}
  }
  return $null
}
function Run-Python([string[]]$PythonArgs){
  if(-not $script:Python -or -not $script:Python.Exe){throw 'Python launcher was not initialized'}
  & $script:Python.Exe @($script:Python.Prefix) @PythonArgs
  if($LASTEXITCODE -ne 0){throw "Python command failed: $($PythonArgs -join ' ')"}
}
function Has-Command([string]$Name){ return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }
function Has-VCTools {
  $v=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
  if(-not(Test-Path $v)){return $false}
  try { return [bool]((& $v -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath).Trim()) } catch { return $false }
}
function Get-MissingDependencies {
  Add-KnownToolPaths
  $m=@()
  $script:Python=Find-Python; if(-not $script:Python){$m+='python'}
  foreach($n in 'cmake','cargo','rustc','rustup','node','npm','npx','perl','tar','git'){if(-not(Has-Command $n)){$m += $n}}
  if(-not(Has-VCTools)){$m += 'msvc'}
  return @($m | Select-Object -Unique)
}
function Install-WingetPackage([string]$Id,[string]$Override='') {
  $winget=Get-Command winget -ErrorAction SilentlyContinue
  if(-not $winget){throw "winget is required for automatic dependency installation. Install App Installer or install the prerequisite manually."}
  $args=@('install','--id',$Id,'-e','--accept-source-agreements','--accept-package-agreements','--disable-interactivity')
  if($Override){$args += @('--override',$Override)}
  Write-Host "Installing $Id ..." -ForegroundColor Cyan
  & $winget.Source @args
  if($LASTEXITCODE -ne 0){throw "winget failed while installing $Id (exit $LASTEXITCODE)"}
}
function Install-MissingDependencies([string[]]$Items) {
  # npm/npx arrive with Node; cargo/rustc arrive with rustup.
  if($Items -contains 'python'){Install-WingetPackage 'Python.Python.3.13'}
  if($Items -contains 'cmake'){Install-WingetPackage 'Kitware.CMake'}
  if(($Items -contains 'cargo') -or ($Items -contains 'rustc') -or ($Items -contains 'rustup')){Install-WingetPackage 'Rustlang.Rustup'}
  if(($Items -contains 'node') -or ($Items -contains 'npm') -or ($Items -contains 'npx')){Install-WingetPackage 'OpenJS.NodeJS.LTS'}
  if($Items -contains 'perl'){Install-WingetPackage 'StrawberryPerl.StrawberryPerl'}
  if($Items -contains 'git'){Install-WingetPackage 'Git.Git'}
  if($Items -contains 'msvc'){
    Install-WingetPackage 'Microsoft.VisualStudio.2022.BuildTools' '--wait --passive --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended'
  }
  if($Items -contains 'tar'){Write-Warning 'tar.exe is normally included with Windows 10/11. Automatic replacement is intentionally not installed.'}
  Refresh-ProcessPath
}
function Describe-Missing([string]$Name) {
  switch($Name){
    'python' {'Python 3.9+ (auto: winget install --id Python.Python.3.13 -e)'}
    'cmake' {'CMake (auto: winget install --id Kitware.CMake -e)'}
    'cargo' {'Rust/Cargo (auto: winget install --id Rustlang.Rustup -e)'}
    'rustc' {'Rust compiler (auto: winget install --id Rustlang.Rustup -e)'}
    'rustup' {'Rustup (auto: winget install --id Rustlang.Rustup -e)'}
    'node' {'Node.js LTS (auto: winget install --id OpenJS.NodeJS.LTS -e)'}
    'npm' {'npm (installed with Node.js LTS)'}
    'npx' {'npx (installed with Node.js LTS)'}
    'perl' {'Strawberry Perl; C:\Strawberry\perl\bin is auto-detected'}
    'msvc' {'Visual Studio Build Tools 2022 + Desktop development with C++'}
    'tar' {'tar.exe (normally included with Windows 10/11)'}
    'git' {'Git for Windows (auto: winget install --id Git.Git -e)'}
    default {$Name}
  }
}

Add-KnownToolPaths
$Missing=Get-MissingDependencies
if($Missing.Count -and -not $Plan){
  Write-Host ''; Write-Host 'Missing prerequisites:' -ForegroundColor Yellow
  $Missing | ForEach-Object { Write-Host "  - $(Describe-Missing $_)" -ForegroundColor Yellow }
  if(Has-Command winget){
    $answer = if($InstallDependencies){'Y'}else{Read-Host 'Install supported missing dependencies automatically with winget? [Y/N]'}
    if($answer -match '^(?i:y|yes|j|ja)$'){
      Install-MissingDependencies $Missing
      $Missing=Get-MissingDependencies
    }
  }
}
Write-Host 'QRX native Windows x64 release plan:'
Write-Host '  0. Preflight all Windows dependencies + GUI/Core audits'
Write-Host '  1. Hermetic MSVC Core/CLI/QRXDB build'
Write-Host '  2. Stage CLI/Python tools'
Write-Host '  3. Build BTC wallet service (x86_64-pc-windows-msvc)'
Write-Host '  4. Build QRX Browser sidecar'
Write-Host '  5. Stage target-suffixed Tauri sidecars'
Write-Host '  6. Stage AURA + verified Windows AI bundle'
Write-Host '  7. Build Tauri MSI + NSIS installers'
Write-Host '  8. Verify and package SHA-256 release'
if($Missing.Count){ Write-Host ''; Write-Host 'Missing prerequisites:' -ForegroundColor Red; $Missing|ForEach-Object{Write-Host "  - $(Describe-Missing $_)" -ForegroundColor Red}; if($Plan){exit 4}; throw 'Windows build preflight failed. Install the items above and rerun. QRX 0.0.9.83 refreshes common tool paths automatically.' }
if($Plan){Write-Host 'Windows preflight: PASS'; exit 0}

$Core=Join-Path $Repo 'qrx-core'; $Wallet=Join-Path $Repo 'GUIWALLET'; $Browser=Join-Path $Repo 'QRXBROWSER'
$BuildRoot=if($env:QRX_BUILD_DIR){$env:QRX_BUILD_DIR}else{Join-Path $Repo 'build'}
$DistRoot=if($env:QRX_DIST_DIR){$env:QRX_DIST_DIR}else{Join-Path $Repo 'dist'}
$CoreBuild=Join-Path $BuildRoot 'core\windows-x64'; $Deps=Join-Path $BuildRoot 'deps\windows-x64'; $CargoTarget=Join-Path $BuildRoot 'tauri\windows-x64'; $BrowserTarget=Join-Path $BuildRoot 'browser-cargo'; $Out=Join-Path $DistRoot 'windows-x64'
$RustTarget='x86_64-pc-windows-msvc'; $Jobs=[Environment]::ProcessorCount
New-Item -ItemType Directory -Force -Path $BuildRoot,$DistRoot | Out-Null
if(Test-Path $Out){Remove-Item -Recurse -Force $Out}; New-Item -ItemType Directory -Force -Path (Join-Path $Out 'core'),(Join-Path $Out 'tools'),(Join-Path $Out 'wallet')|Out-Null

Write-Host '[0/8] Auditing GUI <-> Core/CLI compatibility'
foreach($a in 'audit-gui-core-compat.py','audit-gui-interactions.py','audit-gui-polish.py','audit-tauri2-browser.py'){Run-Python @((Join-Path $Repo "scripts\$a"))}

Write-Host '[1/8] Building Core and native command-line tools with MSVC'
& (Join-Path $Core 'scripts\build-windows-x64-static.ps1') -BuildDir $CoreBuild -DepsPrefix $Deps -Jobs $Jobs
$CoreBin=Join-Path $CoreBuild 'Release'
$bins='qrx','qrx-cli','qrxd','qrx-upscaler','qrxdb_verify','qrxdb_salvage','qrxdb_compact','qrxdb_snapshot'
foreach($b in $bins){$p=Join-Path $CoreBin "$b.exe"; if(-not(Test-Path $p)){throw "Core output missing: $p"}; Copy-Item $p (Join-Path $Out "core\$b.exe") -Force}

# Cargo crates such as openssl-sys cannot discover QRX's private Windows
# dependency prefix through CMake. Point every later Rust/Tauri build at the
# same verified static OpenSSL installation used by the native Core.
$env:OPENSSL_DIR=$Deps
$env:OPENSSL_LIB_DIR=Join-Path $Deps 'lib'
$env:OPENSSL_INCLUDE_DIR=Join-Path $Deps 'include'
$env:OPENSSL_STATIC='1'

Write-Host '[2/8] Staging complete CLI and Python tool set'
Copy-Item (Join-Path $Core 'tools\qrx-wallet-cli.py'),(Join-Path $Core 'tools\qrx-complete-ledger-export.py'),(Join-Path $Core 'gateways\qrx-arbitrage-engine.py'),(Join-Path $Core 'gateways\qrx-gateway-kraken.py') (Join-Path $Out 'tools') -Force

Write-Host '[3/8] Building shared Rust BTC wallet service'
& rustup target add $RustTarget; if($LASTEXITCODE -ne 0){throw 'rustup target add failed'}
$env:CARGO_TARGET_DIR=$CargoTarget
$btcManifest=Join-Path $Wallet 'btc-wallet-service\Cargo.toml'; $btcLock=Join-Path $Wallet 'btc-wallet-service\Cargo.lock'
$ca=@('build','--manifest-path',$btcManifest,'--release','--target',$RustTarget); if(Test-Path $btcLock){$ca=@('build','--locked','--manifest-path',$btcManifest,'--release','--target',$RustTarget)}
& cargo @ca; if($LASTEXITCODE -ne 0){throw 'BTC wallet service build failed'}
$btc=Join-Path $CargoTarget "$RustTarget\release\qrx-btc-wallet-service.exe"; if(-not(Test-Path $btc)){throw "BTC service missing: $btc"}; Copy-Item $btc (Join-Path $Out 'core\qrx-btc-wallet-service.exe') -Force

Write-Host '[4/8] Building isolated Tauri 2 QRX Browser sidecar'
$bm=Join-Path $Browser 'src-tauri\Cargo.toml'; New-Item -ItemType Directory -Force -Path $BrowserTarget|Out-Null
if(-not(Test-Path (Join-Path $Browser 'src-tauri\Cargo.lock'))){$env:CARGO_TARGET_DIR=$BrowserTarget; & cargo generate-lockfile --manifest-path $bm; if($LASTEXITCODE -ne 0){throw 'Browser lockfile generation failed'}}
$env:CARGO_TARGET_DIR=$BrowserTarget; & cargo build --locked --manifest-path $bm --release --target $RustTarget; if($LASTEXITCODE -ne 0){throw 'QRX Browser build failed'}
$browserBin=Join-Path $BrowserTarget "$RustTarget\release\qrx-browser.exe"; if(-not(Test-Path $browserBin)){throw "Browser binary missing: $browserBin"}; Copy-Item $browserBin (Join-Path $Out 'core\qrx-browser.exe') -Force

Write-Host '[5/8] Installing exact target-suffixed Tauri sidecars'
$TauriBin=Join-Path $Wallet 'src-tauri\bin'; New-Item -ItemType Directory -Force -Path $TauriBin|Out-Null
foreach($b in 'qrx','qrx-cli','qrxd','qrx-upscaler'){Copy-Item (Join-Path $CoreBin "$b.exe") (Join-Path $TauriBin "$b-$RustTarget.exe") -Force}
Copy-Item $btc (Join-Path $TauriBin "qrx-btc-wallet-service-$RustTarget.exe") -Force; Copy-Item $browserBin (Join-Path $TauriBin "qrx-browser-$RustTarget.exe") -Force

Write-Host '[6/8] Staging AURA and verified Windows AI resources'
$Aura=Join-Path $Wallet 'src-tauri\resources\aura'; New-Item -ItemType Directory -Force -Path $Aura|Out-Null
if($env:QRX_AURA_RUNTIME_CATALOG -and $env:QRX_AURA_RUNTIME_PUBLISHER_KEY){Copy-Item $env:QRX_AURA_RUNTIME_CATALOG (Join-Path $Aura 'official-runtime-catalog.qrx') -Force; Copy-Item $env:QRX_AURA_RUNTIME_PUBLISHER_KEY (Join-Path $Aura 'official-runtime-publisher.pem') -Force}else{Remove-Item (Join-Path $Aura 'official-runtime-catalog.qrx'),(Join-Path $Aura 'official-runtime-publisher.pem') -Force -ErrorAction SilentlyContinue; if($env:QRX_REQUIRE_AURA_RUNTIME_RESOURCES -eq '1'){throw 'AURA release resources required but not configured'}; Write-Warning 'AURA signed runtime resources not staged (development build).'}
$aiDest=Join-Path $Wallet 'src-tauri\resources\upscaler'
try { & (Join-Path $Repo 'scripts\prepare-upscaler-ai-bundle-windows.ps1') -Destination $aiDest; if($LASTEXITCODE -ne 0){throw 'AI staging failed'} } catch { if($env:QRX_ALLOW_AI_PENDING -ne '1'){throw}; Remove-Item $aiDest -Recurse -Force -ErrorAction SilentlyContinue; Write-Warning 'QRX_ALLOW_AI_PENDING=1: AI Upscaler unavailable in this developer build.' }
if(Test-Path $aiDest){Run-Python @((Join-Path $Repo 'scripts\verify-upscaler-ai-bundle.py'),$aiDest,'windows-x64')}

Write-Host '[7/8] Building Tauri MSI + NSIS wallet'
Push-Location $Wallet
try{$env:CARGO_TARGET_DIR=$CargoTarget; if((Test-Path 'package-lock.json') -or (Test-Path 'npm-shrinkwrap.json')){& npm ci --no-audit --no-fund}else{Write-Warning 'No npm lock file: build is not reproducible'; & npm install --no-audit --no-fund}; if($LASTEXITCODE -ne 0){throw 'npm dependency install failed'}; & npx tauri build --target $RustTarget --config 'src-tauri/tauri.windows.conf.json'; if($LASTEXITCODE -ne 0){throw 'Tauri Windows build failed'}} finally{Pop-Location}
$Bundle=Join-Path $CargoTarget "$RustTarget\release\bundle"; if(-not(Test-Path $Bundle)){throw "Tauri bundle missing: $Bundle"}
$msi=Get-ChildItem $Bundle -Recurse -File -Filter *.msi -ErrorAction SilentlyContinue|Select-Object -First 1; $installer=Get-ChildItem $Bundle -Recurse -File -Filter *.exe -ErrorAction SilentlyContinue|Where-Object{$_.Name -match 'setup|installer|nsis'}|Select-Object -First 1
if(-not $msi){throw 'Windows MSI missing after Tauri bundle'}; if(-not $installer){throw 'Windows NSIS installer EXE missing after Tauri bundle'}
Copy-Item (Join-Path $Bundle '*') (Join-Path $Out 'wallet') -Recurse -Force

Write-Host '[8/8] Verifying and packaging checksummed release'
foreach($b in @('qrx','qrx-cli','qrxd','qrx-upscaler','qrx-btc-wallet-service','qrx-browser')){if(-not(Test-Path (Join-Path $Out "core\$b.exe"))){throw "Release binary missing: $b"}}
$zip=Join-Path $DistRoot 'qrx-0.0.9-genesis-windows-x64.zip'; Run-Python @((Join-Path $Repo 'scripts\package-target-release.py'),'--root',$Out,'--target','windows-x64','--output',$zip)
$hash=(Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant(); Write-Host "QRX Windows x64 release complete: $zip"; Write-Host "SHA256: $hash"
