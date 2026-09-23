from pathlib import Path
r=Path(__file__).resolve().parents[1]
a=(r/'scripts/build-all-targets.ps1').read_text()
b=(r/'qrx-core/scripts/build-windows-x64-static.ps1').read_text()
assert "'git'" in a and "Install-WingetPackage 'Git.Git'" in a
assert r"C:\Program Files\Git\cmd" in a
assert 'foreach ($c in @("cmake","perl","tar","git"))' in b
assert '$TarExe = Join-Path $env:SystemRoot "System32\\tar.exe"' in b
assert '& $TarExe -xf $Archive --strip-components=1 -C $Destination' in b
assert 'curl-$CurlVersion.tar.gz' in b
assert 'curl-$CurlVersion.tar.xz' not in b
assert 'd54dd598bf05927a726deb38df31c6a255ba83ff1de57c5d1464dac3ed8f44a1' in b
assert "$DepsPrefixCMake=$DepsPrefix -replace '\\\\','/'" in b
assert "$ZlibStaticCMake=$ZlibStatic -replace '\\\\','/'" in b
assert '"-DZLIB_LIBRARY=$ZlibStaticCMake"' in b
assert '"-DZLIB_LIBRARY=$ZlibStatic"' not in b
assert 'https://github.com/madler/zlib/releases/download/v$ZlibVersion/' in b
assert '[string[]]$ConfigureArgs' in b and '@ConfigureArgs' in b
assert '[string[]]$Args' not in b and '@Args' not in b
assert '$CMakeGenerator="Visual Studio 17 2022"' in b
assert '-G $CMakeGenerator -A x64' in b
assert '"-G",$CMakeGenerator,"-A","x64"' in b
assert '& cmake -S $Source -B $Build -A x64' not in b
print('QRX 0.0.9.93 Windows CMake/Git bootstrap audit: PASS')
