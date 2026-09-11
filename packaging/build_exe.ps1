<#
Build SignupFixtureLab.exe on Windows, and (with -SmokeTest) boot it to prove the bundle works.

PyInstaller is not a cross-compiler, so this only ever runs on Windows. It is the CI-safe twin of
build_exe.bat: that one ends in `pause`, which is right for a double-click and would hang a
runner. The two must pass the same flags -- tests/test_lint.py compares them.
#>
param(
    [switch]$SmokeTest,
    [string]$Port = '8010'
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

python -m PyInstaller --noconfirm --clean --onefile --console `
  --name SignupFixtureLab `
  --add-data 'seeds\schema.sql;seeds' `
  --collect-submodules console --collect-submodules seeds `
  --collect-submodules load --collect-submodules mockapi --collect-submodules abuse `
  console\__main__.py
if ($LASTEXITCODE) { throw "pyinstaller exited $LASTEXITCODE" }

$exe = Join-Path $repo 'dist\SignupFixtureLab.exe'
if (-not (Test-Path $exe)) { throw "no $exe after the build" }
Write-Host ('built {0} ({1} MB)' -f $exe, [math]::Round((Get-Item $exe).Length / 1MB, 1))
if (-not $SmokeTest) { return }

# What a double-click is supposed to do, checked on the only platform where the promise is at
# risk: a frozen build seeds bootstrap_accounts on first run, and anchors its relative paths to
# the folder holding the .exe -- so var\ belongs in dist\, not wherever this was launched from.
$out = Join-Path $repo 'dist\smoke.log'
$proc = Start-Process -FilePath $exe -ArgumentList @('--port', $Port) `
  -WorkingDirectory $repo -WindowStyle Hidden -PassThru `
  -RedirectStandardOutput $out -RedirectStandardError 'dist\smoke.err'
try {
    $state = $null
    for ($i = 0; $i -lt 45; $i++) {
        Start-Sleep -Seconds 2
        try {
            $state = Invoke-RestMethod ("http://127.0.0.1:{0}/api/state" -f $Port) -TimeoutSec 5
            if ($state.fixture.tables.users -ge 1) { break }
        } catch { }
    }
    if ($null -eq $state) { throw 'the .exe never answered /api/state' }
    $users = $state.fixture.tables.users
    if ($users -lt 5) { throw "first run seeded $users accounts; expected bootstrap_accounts (5)" }
    $list = Join-Path $repo 'dist\var\accounts.txt'
    if (-not (Test-Path $list)) { throw "no $list : the account list did not land next to the .exe" }
    $listed = @(Get-Content $list | Where-Object { $_ -and $_ -notmatch '^#' }).Count
    if ($listed -lt 5) { throw "$list lists $listed accounts; expected 5" }
    Write-Host "smoke ok: $users accounts seeded, $listed listed at $list"
} finally {
    if ($null -ne $proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
    Get-Content $out, (Join-Path $repo 'dist\smoke.err') -ErrorAction SilentlyContinue | Select-Object -Last 30
}
