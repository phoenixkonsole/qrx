param(
  [string]$BuildDir = "",
  [int]$Jobs = 0,
  [string]$DepsPrefix = ""
)
$ErrorActionPreference = "Stop"
# Strawberry Perl may be installed correctly while the current shell still has an old PATH.
foreach($p in @("C:\Strawberry\perl\bin","C:\Strawberry\c\bin")){
  if((Test-Path $p) -and (($env:Path -split ';') -notcontains $p)){ $env:Path="$p;$env:Path" }
}
$Core = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Repo = (Resolve-Path (Join-Path $Core "..")).Path
if (-not $BuildDir) { $BuildDir = Join-Path $Repo "build\core\windows-x64" }
if (-not $DepsPrefix) { $DepsPrefix = Join-Path $Repo "build\deps\windows-x64" }
$DepsPrefixCMake=$DepsPrefix -replace '\\','/'
if ($Jobs -le 0) { $Jobs = [Environment]::ProcessorCount }
$SourceCache = Join-Path $Repo "build\deps\sources"
$Work = Join-Path $Repo "build\deps\work\windows-x64"
New-Item -ItemType Directory -Force -Path $DepsPrefix,$SourceCache,$Work | Out-Null

$OpenSSLVersion = if ($env:QRX_OPENSSL_VERSION) { $env:QRX_OPENSSL_VERSION } else { "3.6.4" }
$ZlibVersion = if ($env:QRX_ZLIB_VERSION) { $env:QRX_ZLIB_VERSION } else { "1.3.2" }
$PngVersion = if ($env:QRX_LIBPNG_VERSION) { $env:QRX_LIBPNG_VERSION } else { "1.6.58" }
$CurlVersion = if ($env:QRX_CURL_VERSION) { $env:QRX_CURL_VERSION } else { "8.22.0" }
$ZlibSha = "bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16"
$PngSha = "28eb403f51f0f7405249132cecfe82ea5c0ef97f1b32c5a65828814ae0d34775"
$CurlSha = "d54dd598bf05927a726deb38df31c6a255ba83ff1de57c5d1464dac3ed8f44a1"

function Need([string]$Name) { if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) { throw "Missing build tool: $Name" } }
foreach ($c in @("cmake","perl","tar","git")) { Need $c }
$TarExe = Join-Path $env:SystemRoot "System32\tar.exe"
if (-not (Test-Path $TarExe)) { throw "Windows tar.exe not found: $TarExe" }

function Fetch([string]$Url,[string]$Out) {
  if (-not (Test-Path $Out) -or (Get-Item $Out).Length -eq 0) {
    Write-Host "Downloading $Url"
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile "$Out.tmp"
    Move-Item -Force "$Out.tmp" $Out
  }
}
function Verify([string]$File,[string]$Expected) {
  $got=(Get-FileHash -Algorithm SHA256 $File).Hash.ToLowerInvariant()
  if ($got -ne $Expected.ToLowerInvariant()) { throw "SHA256 mismatch for $File`nexpected $Expected`nactual   $got" }
}
function FetchVerified([string]$Url,[string]$Out,[string]$Expected) {
  # Never trust a stale or mirror/error-page cache entry. Verify first, then
  # delete and download exactly once if the cached bytes are not the pinned artifact.
  if (Test-Path $Out) {
    $cached=(Get-FileHash -Algorithm SHA256 $Out).Hash.ToLowerInvariant()
    if ($cached -ne $Expected.ToLowerInvariant()) {
      Write-Warning "Discarding cached source with wrong SHA256: $Out"
      Remove-Item -Force $Out
    }
  }
  Fetch $Url $Out
  Verify $Out $Expected
}
function Extract([string]$Archive,[string]$Destination) {
  Write-Host "Extracting $Archive -> $Destination"
  if (Test-Path $Destination) { Remove-Item -Recurse -Force $Destination }
  New-Item -ItemType Directory -Force -Path $Destination | Out-Null
  # GitHub Actions invokes this script from Git Bash, whose /usr/bin/tar sees
  # native paths such as D:\a\... as remote host syntax ("Cannot connect to
  # D:").  Call the Windows tar executable explicitly so native paths remain
  # native on every Windows entry point.
  & $TarExe -xf $Archive --strip-components=1 -C $Destination
  if ($LASTEXITCODE -ne 0) { throw "Failed to extract $Archive" }
  Write-Host "Extracted $Archive"
}

$OsslTar=Join-Path $SourceCache "openssl-$OpenSSLVersion.tar.gz"
$OsslShaFile="$OsslTar.sha256"
Fetch "https://github.com/openssl/openssl/releases/download/openssl-$OpenSSLVersion/openssl-$OpenSSLVersion.tar.gz" $OsslTar
Fetch "https://github.com/openssl/openssl/releases/download/openssl-$OpenSSLVersion/openssl-$OpenSSLVersion.tar.gz.sha256" $OsslShaFile
$OsslExpected=((Get-Content $OsslShaFile | Select-Object -First 1) -split '\s+')[0]
if ($OsslExpected -notmatch '^[0-9a-fA-F]{64}$') { throw "Invalid OpenSSL checksum sidecar" }
Verify $OsslTar $OsslExpected
$ZlibTar=Join-Path $SourceCache "zlib-$ZlibVersion.tar.gz"; Fetch "https://github.com/madler/zlib/releases/download/v$ZlibVersion/zlib-$ZlibVersion.tar.gz" $ZlibTar; Verify $ZlibTar $ZlibSha
$PngTar=Join-Path $SourceCache "libpng-$PngVersion.tar.xz"
$PngArchiveOk=$false
try {
  FetchVerified "https://downloads.sourceforge.net/project/libpng/libpng16/$PngVersion/libpng-$PngVersion.tar.xz?download=1" $PngTar $PngSha
  $PngArchiveOk=$true
} catch {
  Write-Warning "Canonical libpng archive fetch did not produce the maintainer-published SHA256; refusing those bytes and falling back to the signed/tagged upstream source tree."
  Remove-Item -Force -ErrorAction SilentlyContinue $PngTar,"$PngTar.tmp"
}
$PngGitSource=Join-Path $Work "libpng-$PngVersion-git"
if (-not $PngArchiveOk) {
  Need "git"
  $PngCommit="3061454d980de7d53608f594194cfac722721d2a"
  if (Test-Path $PngGitSource) { Remove-Item -Recurse -Force $PngGitSource }
  # Clone the exact upstream release tag directly.  Do not reconstruct a
  # refs/tags ref after clone: PowerShell/string changes in 0.0.9.91 could
  # accidentally turn v1.6.58 into v/tags/v1.6.58.
  $PngTag="v$PngVersion"
  & git clone --filter=blob:none --depth 1 --branch $PngTag --single-branch https://github.com/pnggroup/libpng.git $PngGitSource
  if ($LASTEXITCODE -ne 0) { throw "libpng upstream tagged clone failed ($PngTag)" }
  $tagCommit=(& git -C $PngGitSource rev-parse HEAD).Trim().ToLowerInvariant()
  if ($LASTEXITCODE -ne 0 -or -not $tagCommit) { throw "libpng tagged HEAD resolution failed" }
  if ($tagCommit -ne $PngCommit) { throw "libpng tag commit mismatch`nexpected $PngCommit`nactual   $tagCommit" }
  $exactTag=(& git -C $PngGitSource describe --tags --exact-match HEAD).Trim()
  if ($LASTEXITCODE -ne 0 -or $exactTag -ne $PngTag) { throw "libpng checkout is not exact expected tag $PngTag (actual '$exactTag')" }
  & git -C $PngGitSource checkout --detach $PngCommit
  if ($LASTEXITCODE -ne 0) { throw "libpng pinned commit checkout failed" }
}
# Windows' bundled bsdtar extracted gzip sources above correctly, but hung
# indefinitely while opening curl's XZ archive on the hosted VS 2022 runner.
# curl publishes the same signed release as gzip, so use that Windows-native
# compatible format and keep its exact official bytes SHA-256 pinned.
$CurlTar=Join-Path $SourceCache "curl-$CurlVersion.tar.gz"; Fetch "https://curl.se/download/curl-$CurlVersion.tar.gz" $CurlTar; Verify $CurlTar $CurlSha

# OpenSSL's Windows build requires the MSVC developer environment. Locate it
# without depending on vcpkg/Chocolatey/Homebrew-like package managers.
$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "Visual Studio vswhere.exe not found" }
$vsroot = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath).Trim()
if (-not $vsroot) { throw "Visual Studio C++ toolchain not found" }
$vcvars = Join-Path $vsroot "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found: $vcvars" }

$Crypto=Join-Path $DepsPrefix "lib\libcrypto.lib"
$OpenSSLSource=Join-Path $Work "openssl-$OpenSSLVersion"
if (-not (Test-Path $Crypto)) {
  Extract $OsslTar $OpenSSLSource
  $cmd='"{0}" && cd /d "{1}" && perl Configure VC-WIN64A no-shared no-tests no-asm --prefix="{2}" --openssldir="{2}\ssl" && nmake && nmake install_sw' -f $vcvars,$OpenSSLSource,$DepsPrefix
  & cmd.exe /d /s /c $cmd
  if ($LASTEXITCODE -ne 0) { throw "OpenSSL source build failed" }
}
if (-not (Test-Path $Crypto)) { $Crypto=Join-Path $DepsPrefix "lib\crypto.lib" }
if (-not (Test-Path $Crypto)) { throw "Static OpenSSL crypto library missing" }

# OpenSSL requires applink.c to be compiled into MSVC applications which use
# its stdio APIs. install_sw does not install that source file, so adopt it
# from the same verified source archive used to build libcrypto.
$OpenSSLApplink=Join-Path $DepsPrefix "include\openssl\applink.c"
if (-not (Test-Path $OpenSSLApplink)) {
  $SourceApplink=Join-Path $OpenSSLSource "ms\applink.c"
  if (-not (Test-Path $SourceApplink)) {
    Extract $OsslTar $OpenSSLSource
  }
  if (-not (Test-Path $SourceApplink)) { throw "OpenSSL applink source missing from verified archive" }
  Copy-Item -Force $SourceApplink $OpenSSLApplink
}

# Pin the multi-config Visual Studio generator.  Passing -A x64 to an
# environment-selected Ninja generator is invalid (Ninja has no platform
# specification) and also leaves cl.exe undiscovered outside a VS dev shell.
# The Windows preflight already requires the VS 2022 C++ toolchain, so use its
# generator deterministically for dependency and Core builds.
$CMakeGenerator="Visual Studio 17 2022"
function CMakeInstall([string]$Source,[string]$Build,[string[]]$ConfigureArgs) {
  if (Test-Path $Build) { Remove-Item -Recurse -Force $Build }
  # $args is PowerShell's automatic collection for undeclared arguments and
  # is case-insensitive.  A parameter named $Args therefore swallowed these
  # dependency options on clean runners.  Use a distinct splat name.
  & cmake -S $Source -B $Build -G $CMakeGenerator -A x64 @ConfigureArgs
  if ($LASTEXITCODE -ne 0) { throw "CMake configure failed: $Source" }
  & cmake --build $Build --config Release --parallel $Jobs
  if ($LASTEXITCODE -ne 0) { throw "CMake build failed: $Source" }
  # --prefix is deliberately repeated at install time. Some upstream CMake
  # projects/cache states can otherwise retain their own default prefix.
  & cmake --install $Build --config Release --prefix $DepsPrefix
  if ($LASTEXITCODE -ne 0) { throw "CMake install failed: $Source" }
}

# Resolve a dependency produced by the *current* build rather than assuming
# every upstream project honours the same install layout.  The resolver is
# intentionally bounded: dependency prefix -> current build tree -> current
# install_manifest.  It never scans arbitrary old system installations.
function Resolve-ZlibStatic([string]$Build,[string]$Source,[string]$Prefix) {
  $destLib=Join-Path $Prefix "lib"
  $destInc=Join-Path $Prefix "include"
  New-Item -ItemType Directory -Force -Path $destLib,$destInc | Out-Null

  $preferred=@(
    (Join-Path $destLib "zlibstatic.lib"),
    (Join-Path $destLib "zs.lib"),
    (Join-Path $destLib "z.lib"),
    (Join-Path $Build "Release\zlibstatic.lib"),
    (Join-Path $Build "Release\zs.lib"),
    (Join-Path $Build "zlibstatic.lib"),
    (Join-Path $Build "zs.lib"),
    (Join-Path $Build "Release\z.lib"),
    (Join-Path $Build "z.lib")
  )
  $candidate=$preferred | Where-Object { Test-Path $_ } | Select-Object -First 1

  # If the expected names moved, consult only this build's manifest and tree.
  if (-not $candidate) {
    $manifest=Join-Path $Build "install_manifest.txt"
    if (Test-Path $manifest) {
      $candidate=Get-Content $manifest | Where-Object {
        $_ -match '\.(lib)$' -and (Split-Path $_ -Leaf) -match '^(zlibstatic|zlib|zs|z)\.lib$'
      } | Where-Object { Test-Path $_ } | Select-Object -First 1
    }
  }
  if (-not $candidate) {
    $candidate=(Get-ChildItem $Build -Recurse -File -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -match '^(zlibstatic|zlib|zs|z)\.lib$' } |
      Sort-Object @{Expression={ if ($_.Name -eq 'zlibstatic.lib') {0} else {1} }},FullName |
      Select-Object -First 1).FullName
  }
  if (-not $candidate -or -not (Test-Path $candidate)) { return $null }

  # Prefer an explicitly static archive. zlib 1.3.2 calls its MSVC static
  # artifact zs.lib; a bare z.lib next to z.dll can be an import library.
  if ((Split-Path $candidate -Leaf) -ne 'zlibstatic.lib') {
    $explicit=(Get-ChildItem $Build -Recurse -File -Filter 'zlibstatic.lib' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
    if ($explicit) { $candidate=$explicit }
  }

  $canonical=Join-Path $destLib "zlibstatic.lib"
  if ((Resolve-Path $candidate).Path -ne $canonical) {
    Write-Host "Adopting zlib artifact from current build: $candidate"
    Copy-Item -Force $candidate $canonical
  }

  # Adopt headers from the current source/build if upstream installed elsewhere.
  foreach($h in @('zlib.h','zconf.h')) {
    $dst=Join-Path $destInc $h
    if (-not (Test-Path $dst)) {
      $hc=@((Join-Path $Build $h),(Join-Path $Source $h)) | Where-Object { Test-Path $_ } | Select-Object -First 1
      if (-not $hc) {
        $manifest=Join-Path $Build 'install_manifest.txt'
        if (Test-Path $manifest) { $hc=Get-Content $manifest | Where-Object { (Split-Path $_ -Leaf) -eq $h -and (Test-Path $_) } | Select-Object -First 1 }
      }
      if ($hc) { Copy-Item -Force $hc $dst }
    }
  }
  if (-not (Test-Path (Join-Path $destInc 'zlib.h')) -or -not (Test-Path (Join-Path $destInc 'zconf.h'))) {
    throw "zlib library was found, but matching headers from the current build could not be adopted"
  }
  return $canonical
}

$ZlibBuild=Join-Path $Work "zlib-build"
$ZlibSource=Join-Path $Work "zlib-$ZlibVersion"
$ZlibStatic=Resolve-ZlibStatic $ZlibBuild $ZlibSource $DepsPrefix
if (-not $ZlibStatic) {
  Extract $ZlibTar $ZlibSource
  CMakeInstall $ZlibSource $ZlibBuild @(
    "-DCMAKE_BUILD_TYPE=Release","-DCMAKE_INSTALL_PREFIX=$DepsPrefixCMake",
    "-DBUILD_SHARED_LIBS=OFF","-DZLIB_BUILD_SHARED=OFF","-DZLIB_BUILD_STATIC=ON","-DZLIB_BUILD_TESTING=OFF"
  )
  $ZlibStatic=Resolve-ZlibStatic $ZlibBuild $ZlibSource $DepsPrefix
}
if (-not $ZlibStatic -or -not (Test-Path $ZlibStatic)) { throw "Static zlib missing after build/artifact resolution" }
$ZlibStaticCMake=$ZlibStatic -replace '\\','/'

$PngStatic=(Get-ChildItem (Join-Path $DepsPrefix "lib") -Filter "*png*static*.lib" -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
if (-not $PngStatic) {
  if ($PngArchiveOk) { $src=Join-Path $Work "libpng-$PngVersion"; Extract $PngTar $src } else { $src=$PngGitSource }
  CMakeInstall $src (Join-Path $Work "libpng-build") @("-DCMAKE_BUILD_TYPE=Release","-DCMAKE_INSTALL_PREFIX=$DepsPrefixCMake","-DBUILD_SHARED_LIBS=OFF","-DPNG_SHARED=OFF","-DPNG_STATIC=ON","-DPNG_TESTS=OFF","-DPNG_TOOLS=OFF","-DZLIB_ROOT=$DepsPrefixCMake","-DZLIB_LIBRARY=$ZlibStaticCMake","-DZLIB_INCLUDE_DIR=$DepsPrefixCMake/include")
  $PngStatic=(Get-ChildItem (Join-Path $DepsPrefix "lib") -Filter "*png*.lib" | Where-Object { $_.Name -notmatch 'dll' } | Select-Object -First 1).FullName
}
if (-not $PngStatic) { throw "Static libpng missing" }

$CurlStatic=Join-Path $DepsPrefix "lib\libcurl.lib"
if (-not (Test-Path $CurlStatic)) {
  $src=Join-Path $Work "curl-$CurlVersion"; Extract $CurlTar $src
  CMakeInstall $src (Join-Path $Work "curl-build") @(
    "-DCMAKE_BUILD_TYPE=Release","-DCMAKE_INSTALL_PREFIX=$DepsPrefixCMake","-DBUILD_SHARED_LIBS=OFF","-DBUILD_CURL_EXE=OFF","-DBUILD_TESTING=OFF",
    "-DCURL_USE_OPENSSL=ON","-DCURL_ZLIB=ON","-DOPENSSL_ROOT_DIR=$DepsPrefixCMake","-DOPENSSL_USE_STATIC_LIBS=TRUE","-DZLIB_ROOT=$DepsPrefixCMake","-DZLIB_LIBRARY=$ZlibStaticCMake",
    "-DCURL_USE_LIBPSL=OFF","-DCURL_BROTLI=OFF","-DCURL_ZSTD=OFF","-DUSE_LIBIDN2=OFF","-DUSE_NGHTTP2=OFF","-DUSE_NGTCP2=OFF","-DUSE_QUICHE=OFF","-DCURL_USE_LIBSSH2=OFF","-DCURL_USE_GSSAPI=OFF",
    "-DCURL_DISABLE_LDAP=ON","-DCURL_DISABLE_LDAPS=ON","-DCURL_DISABLE_FTP=ON","-DCURL_DISABLE_FILE=ON","-DCURL_DISABLE_TELNET=ON","-DCURL_DISABLE_TFTP=ON","-DCURL_DISABLE_DICT=ON","-DCURL_DISABLE_GOPHER=ON","-DCURL_DISABLE_IMAP=ON","-DCURL_DISABLE_POP3=ON","-DCURL_DISABLE_RTSP=ON","-DCURL_DISABLE_SMB=ON","-DCURL_DISABLE_SMTP=ON","-DCURL_DISABLE_MQTT=ON","-DCURL_DISABLE_WEBSOCKETS=ON"
  )
}
if (-not (Test-Path $CurlStatic)) { throw "Static libcurl missing" }

$CryptoCMake=$Crypto -replace '\\','/'
$PngStaticCMake=$PngStatic -replace '\\','/'
$CurlStaticCMake=$CurlStatic -replace '\\','/'

@("openssl=$OpenSSLVersion sha256=$OsslExpected","zlib=$ZlibVersion sha256=$ZlibSha","libpng=$PngVersion archive-sha256=$PngSha git-fallback-commit=3061454d980de7d53608f594194cfac722721d2a","curl=$CurlVersion sha256=$CurlSha","os=windows","arch=x86_64") | Set-Content -Encoding ascii (Join-Path $DepsPrefix "qrx-deps.lock")

if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
$cmakeArgs=@("-S",$Core,"-B",$BuildDir,"-G",$CMakeGenerator,"-A","x64","-DCMAKE_BUILD_TYPE=Release","-DQRX_REQUIRE_PQC=ON","-DQRX_REQUIRE_BUNDLED_DEPS=ON","-DQRX_DEPS_PREFIX=$DepsPrefixCMake","-DOPENSSL_ROOT_DIR=$DepsPrefixCMake","-DOPENSSL_USE_STATIC_LIBS=TRUE","-DOPENSSL_CRYPTO_LIBRARY=$CryptoCMake","-DZLIB_ROOT=$DepsPrefixCMake","-DZLIB_LIBRARY=$ZlibStaticCMake","-DZLIB_INCLUDE_DIR=$DepsPrefixCMake/include","-DPNG_PNG_INCLUDE_DIR=$DepsPrefixCMake/include","-DPNG_LIBRARY=$PngStaticCMake","-DCURL_ROOT=$DepsPrefixCMake","-DCURL_USE_STATIC_LIBS=TRUE","-DCURL_LIBRARY=$CurlStaticCMake","-DCURL_INCLUDE_DIR=$DepsPrefixCMake/include")
& cmake @cmakeArgs; if ($LASTEXITCODE -ne 0) { throw "QRX CMake configure failed" }
& cmake --build $BuildDir --config Release --parallel $Jobs; if ($LASTEXITCODE -ne 0) { throw "QRX build failed" }
$expected=@("qrx.exe","qrx-cli.exe","qrxd.exe","qrx-upscaler.exe","qrxdb_verify.exe","qrxdb_salvage.exe","qrxdb_compact.exe","qrxdb_snapshot.exe")
foreach($name in $expected){$p=Join-Path (Join-Path $BuildDir "Release") $name;if(-not(Test-Path $p)){throw "Expected artifact missing: $p"}}
Write-Host "Hermetic Windows x64 QRX build complete: $BuildDir\Release"
Write-Host "Dependency prefix: $DepsPrefix"
