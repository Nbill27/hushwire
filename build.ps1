<#
.SYNOPSIS
    Build the hushwire single binary.

.DESCRIPTION
    hushwire uses cgo (gopacket/pcap -> libpcap/Npcap), so only host builds are
    supported out of the box. Cross-compiling from Windows to linux/darwin
    needs a cross toolchain (osxcross, x86_64-linux-gnu-gcc) that this script
    does not provide.

.PARAMETER Out
    Output directory. Default: .\dist

.PARAMETER Version
    Version string stamped into the binary. Default: short git sha or 0.1.0-dev

.PARAMETER MinGW
    Directory holding gcc.exe. Default: C:\mingw64\bin

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Version 0.2.0 -Out .\bin
#>
[CmdletBinding()]
param(
    [string]$Out = ".\dist",
    [string]$Version = "",
    [string]$MinGW = "C:\mingw64\bin"
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Fail($msg) { Write-Host "!!  $msg" -ForegroundColor Red }

# ---- go -------------------------------------------------------------------

$go = Get-Command go -ErrorAction SilentlyContinue
if (-not $go) {
    Write-Fail "go not found on PATH. Install Go 1.21+ or add it to PATH."
    exit 1
}
$goVersion = (& go version) -join " "
Write-Step "toolchain: $goVersion"

# ---- cgo toolchain --------------------------------------------------------

if (-not $env:CGO_ENABLED) { $env:CGO_ENABLED = "1" }

$gcc = Get-Command gcc -ErrorAction SilentlyContinue
if (-not $gcc -and (Test-Path (Join-Path $MinGW "gcc.exe"))) {
    $env:PATH = "$MinGW;" + $env:PATH
    $gcc = Get-Command gcc -ErrorAction SilentlyContinue
}
if (-not $gcc) {
    Write-Fail "gcc not found. Install MinGW-w64 and pass -MinGW <dir>, or add it to PATH."
    Write-Fail "cgo is required: gopacket/pcap links against libpcap/Npcap."
    exit 1
}
Write-Step "gcc: $((& gcc --version | Select-Object -First 1))"

$targetOS = (& go env GOOS).Trim()
$targetArch = (& go env GOARCH).Trim()
Write-Step "target: $targetOS/$targetArch (host build only - cgo)"

# ---- version --------------------------------------------------------------

if (-not $Version) {
    $Version = "0.1.0-dev"
    if (Test-Path .git) {
        $sha = (& git rev-parse --short HEAD 2>$null)
        if ($LASTEXITCODE -eq 0 -and $sha) { $Version = "0.1.0-$($sha.Trim())" }
    }
}
Write-Step "version: $Version"

# ---- output dir -----------------------------------------------------------

if (-not (Test-Path $Out)) { New-Item -ItemType Directory -Path $Out | Out-Null }
$Out = (Resolve-Path $Out).Path

$exe = if ($targetOS -eq "windows") { "hushwire.exe" } else { "hushwire" }
$target = Join-Path $Out $exe

# ---- build ----------------------------------------------------------------

# single-token form: avoids PowerShell 5.1 native-argument re-splitting
$ldflags = "-ldflags=-s -w -X main.version=$Version"

Write-Step "go build -> $target"
& go build -trimpath $ldflags -o $target .
if ($LASTEXITCODE -ne 0) {
    Write-Fail "build failed"
    exit $LASTEXITCODE
}

$size = [math]::Round((Get-Item $target).Length / 1MB, 2)
Write-Step "ok: $target ($size MB)"
Write-Host ""
Write-Host "next:" -ForegroundColor DarkGray
Write-Host "  $target --scan                 # one-shot host scan" -ForegroundColor DarkGray
Write-Host "  $target --token <secret>       # serve the web UI" -ForegroundColor DarkGray
