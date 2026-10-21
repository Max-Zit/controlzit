<#
  Builds the ControlZit agent for Windows and its MSI.

    .\packaging\windows\build-msi.ps1 -Version 0.1.0

  Output: dist\controlzit-agent-<version>-x64.msi
  Requires Go, the .NET SDK and WiX 5.0.2 (MS-RL; newer WiX versions carry a
  maintenance-fee EULA, so stay on 5):
    dotnet tool install --global wix --version 5.0.2
    wix extension add -g WixToolset.Util.wixext/5.0.2
    wix extension add -g WixToolset.UI.wixext/5.0.2
  Code signing: pass -SignThumbprint (certificate in the Windows store) or
  set CONTROLZIT_SIGN_THUMBPRINT; without it the files stay unsigned.
#>
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$SignThumbprint = $env:CONTROLZIT_SIGN_THUMBPRINT,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)
$ErrorActionPreference = "Stop"

function Invoke-Sign([string[]]$Files) {
    if (-not $SignThumbprint) { return }
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw "signtool.exe not found; install the Windows SDK (Signing Tools)" }
    foreach ($f in $Files) {
        & $signtool.FullName sign /sha1 $SignThumbprint /fd sha256 /tr $TimestampUrl /td sha256 /d "ControlZit Agent" $f
        if ($LASTEXITCODE -ne 0) { throw "signing $f failed" }
    }
}

$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$dist = Join-Path $root "dist"
$work = Join-Path $root "bin\msi"
New-Item -ItemType Directory -Force $dist, $work | Out-Null

# MSI versions are numeric major.minor.build.
$msiVersion = ($Version -replace '[^0-9.].*$', '')
if ($msiVersion -notmatch '^\d+\.\d+\.\d+$') { throw "Version must start with major.minor.patch, got '$Version'" }

Push-Location $root
try {
    $env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
    if (-not $env:GOTMPDIR) { $env:GOTMPDIR = Join-Path $root ".gotmp"; New-Item -ItemType Directory -Force $env:GOTMPDIR | Out-Null }
    $exe = Join-Path $work "controlzit-agent.exe"
    # Icon, version and publisher as Windows resources of the exe.
    $cmdDir = Join-Path $root "cmd\controlzit-agent"
    Push-Location $cmdDir
    try {
        go run github.com/tc-hib/go-winres@v0.3.3 simply --arch amd64 --manifest cli --icon (Join-Path $root "brand\controlzit-icon-256.png") `
            --product-name "ControlZit Agent" --file-description "ControlZit Agent" --copyright "MaxZit" `
            --original-filename controlzit-agent.exe --product-version "$msiVersion.0" --file-version "$msiVersion.0"
        if ($LASTEXITCODE -ne 0) { throw "go-winres failed" }
    } finally { Pop-Location }
    try {
        go build -trimpath -ldflags "-s -w -X main.version=$Version" -o $exe ./cmd/controlzit-agent
        if ($LASTEXITCODE -ne 0) { throw "go build failed" }
    } finally { Remove-Item (Join-Path $cmdDir "rsrc_windows_amd64.syso") -ErrorAction SilentlyContinue }
    Invoke-Sign $exe

    $wix = Join-Path $env:USERPROFILE ".dotnet\tools\wix.exe"
    if (-not (Test-Path $wix)) { $wix = "wix" }
    $msi = Join-Path $dist "controlzit-agent-$Version-x64.msi"
    & $wix build -ext WixToolset.Util.wixext -ext WixToolset.UI.wixext -arch x64 `
        -d "Version=$msiVersion" -d "AgentExe=$exe" -d "ArtDir=$PSScriptRoot" -d "RootDir=$root" `
        -o $msi (Join-Path $PSScriptRoot "agent.wxs")
    if ($LASTEXITCODE -ne 0) { throw "wix build failed" }
    Invoke-Sign $msi
    Remove-Item (Join-Path $dist "*.wixpdb") -ErrorAction SilentlyContinue
    Write-Host "built $msi"
}
finally {
    Pop-Location
    Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
}
