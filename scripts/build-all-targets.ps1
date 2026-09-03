param(
    [ValidateSet("host", "linux-x64", "linux-arm64", "macos-x64", "macos-arm64", "windows-x64")]
    [string]$Target = "host",
    [switch]$Plan,
    [switch]$All
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BashCandidates = @(
    "$env:ProgramFiles\Git\bin\bash.exe",
    "$env:ProgramFiles\Git\usr\bin\bash.exe"
)
$Bash = $BashCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (!$Bash) {
    $Found = Get-Command bash -ErrorAction SilentlyContinue
    if ($Found) { $Bash = $Found.Source }
}
if (!$Bash) { throw "Git Bash is required. Install Git for Windows first." }

$Args = @("$ScriptDir/build-all-targets.sh")
if ($All) { $Args += "--all" } else { $Args += @("--target", $Target) }
if ($Plan) { $Args += "--plan" }
& $Bash @Args
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
