param([string]$BuildScript = (Join-Path $PSScriptRoot '../qrx-core/scripts/build-windows-x64-static.ps1'))
$ErrorActionPreference = 'Stop'

# Load only the production helper, without downloading or building dependencies.
$source = $BuildScript
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path $source).Path, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "Build script parse errors: $parseErrors" }
$helper = $ast.Find({ param($node)
  $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
  $node.Name -eq 'CMakeInstall'
}, $true)
if (-not $helper) { throw 'CMakeInstall helper not found' }
. ([scriptblock]::Create($helper.Extent.Text))

$script:Calls = New-Object 'System.Collections.Generic.List[object]'
$script:FailConfigure = $false
function cmake {
  $script:Calls.Add(@($args))
  $global:LASTEXITCODE = 0
  if ($script:FailConfigure -and $args[0] -eq '-S') { $global:LASTEXITCODE = 1 }
}
function Assert-Equal($Actual, $Expected, [string]$Label) {
  if ($Actual.Count -ne $Expected.Count) { throw "$Label argument count mismatch" }
  for ($i = 0; $i -lt $Expected.Count; $i++) {
    if ($Actual[$i] -cne $Expected[$i]) { throw "$Label argument ${i}: '$($Actual[$i])' != '$($Expected[$i])'" }
  }
}

$CMakeGenerator = 'Visual Studio 17 2022'
$Jobs = 2
$DepsPrefix = 'C:\QRX test\dependencies'
# The helper removes an existing build directory. Use an absent path, and stop
# if that assumption ever changes, so this regression test cannot remove files.
$build = Join-Path ([IO.Path]::GetTempPath()) ('qrx-cmake-test-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $build) { throw 'Test build path must not exist' }
$src = 'C:\QRX test\libpng'
$options = @('-DBUILD_SHARED_LIBS=OFF', '-DPNG_STATIC=ON',
  "-DCMAKE_INSTALL_PREFIX=$DepsPrefix", "-DZLIB_ROOT=$DepsPrefix",
  "-DZLIB_LIBRARY=$DepsPrefix\lib\zlibstatic.lib", "-DZLIB_INCLUDE_DIR=$DepsPrefix\include")
CMakeInstall $src $build $options
if ($script:Calls.Count -ne 3) { throw 'Expected configure, build and install calls' }
$normalizedOptions=@('-DBUILD_SHARED_LIBS=OFF', '-DPNG_STATIC=ON',
  '-DCMAKE_INSTALL_PREFIX=C:/QRX test/dependencies', '-DZLIB_ROOT=C:/QRX test/dependencies',
  '-DZLIB_LIBRARY=C:/QRX test/dependencies/lib/zlibstatic.lib', '-DZLIB_INCLUDE_DIR=C:/QRX test/dependencies/include')
Assert-Equal $script:Calls[0] (@('-S', $src, '-B', $build, '-G', $CMakeGenerator, '-A', 'x64') + $normalizedOptions) 'configure'
Assert-Equal $script:Calls[1] @('--build', $build, '--config', 'Release', '--parallel', $Jobs) 'build'
Assert-Equal $script:Calls[2] @('--install', $build, '--config', 'Release', '--prefix', $DepsPrefix) 'install'

$script:Calls.Clear()
$script:FailConfigure = $true
$failed = $false
try { CMakeInstall $src $build $options } catch {
  if ($_.Exception.Message -notlike 'CMake configure failed:*') { throw }
  $failed = $true
}
if (-not $failed -or $script:Calls.Count -ne 1) { throw 'Configure failure must stop before build/install' }
$global:LASTEXITCODE = 0
Write-Host 'PASS: CMake options preserve paths with spaces, normalize Windows separators, and configure failure stops the build.'
