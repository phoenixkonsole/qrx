param([string]$BuildScript = (Join-Path $PSScriptRoot '../qrx-core/scripts/build-windows-x64-static.ps1'))
$ErrorActionPreference = 'Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $BuildScript).Path,[ref]$tokens,[ref]$errors)
if($errors.Count) { throw "Parse errors: $errors" }
$helper=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Resolve-ZlibStatic'},$true)
if(-not $helper) { throw 'Resolve-ZlibStatic not found' }
. ([scriptblock]::Create($helper.Extent.Text))
$tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$root=Join-Path $tempRoot ('qrx-zlib-test-' + [guid]::NewGuid().ToString('N'))
try {
  foreach($case in 'installed-zs','build-zs','prefer-static','legacy-static') {
    $prefix=Join-Path $root "$case/prefix"
    $build=Join-Path $root "$case/build"
    $source=Join-Path $root "$case/source"
    New-Item -ItemType Directory -Force -Path "$prefix/lib","$build/Release",$source | Out-Null
    Set-Content "$source/zlib.h" 'current zlib header'
    Set-Content "$build/zconf.h" 'current generated config'
    $artifact=switch($case) {
      'installed-zs' { "$prefix/lib/zs.lib" }
      'build-zs' { "$build/Release/zs.lib" }
      'prefer-static' {
        Set-Content "$prefix/lib/z.lib" 'import library must not win'
        "$build/Release/zs.lib"
      }
      'legacy-static' { "$build/Release/zlibstatic.lib" }
    }
    Set-Content $artifact 'expected static archive'
    $resolved=Resolve-ZlibStatic $build $source $prefix
    if(-not $resolved -or (Get-Content $resolved) -ne 'expected static archive') { throw "$case failed to resolve the static archive" }
    if((Get-Content "$prefix/include/zlib.h") -ne 'current zlib header' -or
       (Get-Content "$prefix/include/zconf.h") -ne 'current generated config') { throw "$case did not adopt matching headers" }
  }
  Write-Host 'PASS: installed/build-tree zs.lib, static-over-import preference, legacy name, and matching headers.'
} finally {
  $resolvedRoot=[IO.Path]::GetFullPath($root)
  if(-not $resolvedRoot.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -or
     (Split-Path $resolvedRoot -Leaf) -notlike 'qrx-zlib-test-*') { throw 'Unsafe cleanup path' }
  if(Test-Path -LiteralPath $resolvedRoot) { Remove-Item -LiteralPath $resolvedRoot -Recurse -Force }
}
