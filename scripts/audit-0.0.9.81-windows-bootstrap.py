from pathlib import Path
root=Path(__file__).resolve().parents[1]
ps=(root/'scripts/build-all-targets.ps1').read_text(encoding='utf-8')
cmd=(root/'scripts/build-windows-x64.cmd').read_text(encoding='ascii')
core=(root/'qrx-core/scripts/build-windows-x64-static.ps1').read_text(encoding='utf-8')
checks={
 'Strawberry autodetect': "C:\\Strawberry\\perl\\bin" in ps,
 'dependency install prompt': 'Install supported missing dependencies automatically with winget?' in ps,
 'Python winget': "Python.Python.3.13" in ps,
 'CMake winget': "Kitware.CMake" in ps,
 'Rustup winget': "Rustlang.Rustup" in ps,
 'Node winget': "OpenJS.NodeJS.LTS" in ps,
 'Perl winget': "StrawberryPerl.StrawberryPerl" in ps,
 'VS Build Tools winget': "Microsoft.VisualStudio.2022.BuildTools" in ps and 'Microsoft.VisualStudio.Workload.VCTools' in ps,
 'policy is process-only': '-ExecutionPolicy Bypass' in cmd and 'Set-ExecutionPolicy' not in cmd,
 'policy consent prompt': 'choice /C YN' in cmd,
 'core Strawberry fallback': 'Strawberry' in core,
 'OpenSSL applink adopted from verified source': 'Copy-Item -Force $SourceApplink $OpenSSLApplink' in core,
 'OpenSSL applink required': 'OpenSSL applink source missing from verified archive' in core,
 'Cargo uses hermetic OpenSSL prefix': '$env:OPENSSL_DIR=$Deps' in ps and "$env:OPENSSL_STATIC='1'" in ps,
}
bad=[k for k,v in checks.items() if not v]
if bad: raise SystemExit('FAIL: '+', '.join(bad))
print('QRX 0.0.9.81 Windows bootstrap audit: PASS')
