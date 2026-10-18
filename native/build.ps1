<#
.SYNOPSIS
  Build the native helpers and copy the artifacts into each package's vendor/.

.DESCRIPTION
  Prefer the in-repo mingw-w64 portable bundle (tools/mingw64, no install, no admin rights);
  fall back to MSVC + Windows SDK (NMake) when it is absent.

  Artifacts: native/bin/<arch>/crash_helper.exe -> packages/dsh-crashlab/vendor/<arch>/

.EXAMPLE
  pwsh native/build.ps1
#>
param(
  [string[]]$Arch = @('x64'),
  [string]$Config = 'Release',
  [string]$MingwRoot = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Split-Path -Parent $root

$cmake = (Get-Command cmake -ErrorAction SilentlyContinue).Source
if (-not $cmake) { throw 'cmake is not on PATH' }

# Keep the compiler temp directory inside the repo: %TEMP% is not writable in some restricted
# sessions, and gcc fails outright when it cannot write there.
$tmp = Join-Path $root 'build\tmp'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$env:TMP = $tmp
$env:TEMP = $tmp

function Find-Mingw([string]$hint) {
  $roots = @()
  if ($hint -ne '') { $roots += $hint }
  $roots += (Join-Path $repo 'tools\mingw64')
  $roots += (Join-Path $repo 'tools')
  foreach ($candidate in $roots) {
    if (-not (Test-Path $candidate)) { continue }
    $gxx = Get-ChildItem $candidate -Recurse -Filter 'g++.exe' -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -match '\\bin\\g\+\+\.exe$' } |
      Select-Object -First 1
    if ($gxx) { return $gxx.FullName }
  }
  return ''
}

$gxx = Find-Mingw $MingwRoot

# Locate MSVC / SDK from the actual local installation; never hardcode version numbers.
# Prefer vswhere (bundled with VS 2017+); if that yields nothing, scan the default install dirs.
$programX86 = ${env:ProgramFiles(x86)}
if (-not $programX86) { $programX86 = 'C:\Program Files (x86)' }
$sdkRoot = Join-Path $programX86 'Windows Kits\10'
$msvcRoot = ''
$vswhere = Join-Path $programX86 'Microsoft Visual Studio\Installer\vswhere.exe'
if (Test-Path $vswhere) {
  $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
  if ($vsPath) { $msvcRoot = Join-Path $vsPath 'VC\Tools\MSVC' }
}
if (-not (Test-Path $msvcRoot)) {
  $msvcRoot = ''
  foreach ($base in @((Join-Path $programX86 'Microsoft Visual Studio'), (Join-Path $env:ProgramFiles 'Microsoft Visual Studio'))) {
    if (-not (Test-Path $base)) { continue }
    $found = Get-ChildItem $base -Recurse -Directory -Filter 'MSVC' -ErrorAction SilentlyContinue |
      Where-Object { Test-Path (Join-Path $_.FullName '*\bin\HostX64\x64\cl.exe') } |
      Select-Object -First 1
    if ($found) { $msvcRoot = $found.FullName; break }
  }
}

$vendorArch = @{ 'x64' = 'x64'; 'Win32' = 'x86' }
$mingwTargets = @{ 'x64' = 'x86_64'; 'Win32' = 'i686' }

foreach ($arch in $Arch) {
  $build = Join-Path $root "build\$arch"
  Remove-Item -Recurse -Force $build -ErrorAction SilentlyContinue

  if ($gxx -ne '') {
    $mingwBin = Split-Path -Parent $gxx
    $gcc = Join-Path $mingwBin 'gcc.exe'
    $env:PATH = "$mingwBin;$env:PATH"
    Write-Host "== mingw toolchain: $mingwBin =="
    & $cmake @(
      '-S', $root, '-B', $build, '-G', 'MinGW Makefiles',
      "-DCMAKE_BUILD_TYPE=$Config",
      "-DCMAKE_C_COMPILER=$gcc",
      "-DCMAKE_CXX_COMPILER=$gxx"
    )
    if ($LASTEXITCODE -ne 0) { throw "cmake configure failed ($arch / mingw)" }
  } else {
    if ($msvcRoot -eq '' -or -not (Test-Path $msvcRoot)) {
      throw 'No C++ toolchain found: extract the mingw-w64 portable bundle into tools\mingw64\, or install Visual Studio with the x64 CRT'
    }
    $msvc = Get-ChildItem $msvcRoot -Directory -ErrorAction SilentlyContinue |
      Where-Object { Test-Path (Join-Path $_.FullName 'bin\HostX64\x64\cl.exe') } |
      Sort-Object Name -Descending | Select-Object -First 1
    if (-not $msvc) { throw 'Neither tools\mingw64 nor a usable MSVC is present: extract the mingw-w64 portable bundle into tools\mingw64\ first' }
    $sdkVer = Get-ChildItem (Join-Path $sdkRoot 'Include') -Directory |
      Sort-Object Name -Descending | Select-Object -First 1

    $hostTriple = @{ 'x64' = 'HostX64\x64'; 'Win32' = 'HostX86\x86' }
    $libArch = @{ 'x64' = 'x64'; 'Win32' = 'x86' }
    $binDir = Join-Path $msvc.FullName "bin\$($hostTriple[$arch])"

    $env:PATH = "$binDir;$(Join-Path $sdkRoot "bin\$($sdkVer.Name)\$($libArch[$arch])");$env:PATH"
    $env:INCLUDE = @(
      (Join-Path $msvc.FullName 'include'),
      (Join-Path $sdkRoot "Include\$($sdkVer.Name)\ucrt"),
      (Join-Path $sdkRoot "Include\$($sdkVer.Name)\um"),
      (Join-Path $sdkRoot "Include\$($sdkVer.Name)\shared"),
      (Join-Path $sdkRoot "Include\$($sdkVer.Name)\winrt")
    ) -join ';'
    $env:LIB = @(
      (Join-Path $msvc.FullName "lib\$($libArch[$arch])"),
      (Join-Path $sdkRoot "Lib\$($sdkVer.Name)\ucrt\$($libArch[$arch])"),
      (Join-Path $sdkRoot "Lib\$($sdkVer.Name)\um\$($libArch[$arch])")
    ) -join ';'

    Write-Host "== MSVC toolchain: $($msvc.Name) / SDK $($sdkVer.Name) =="
    & $cmake -S $root -B $build -G 'NMake Makefiles' -DCMAKE_BUILD_TYPE=$Config -DCMAKE_CXX_COMPILER=cl
    if ($LASTEXITCODE -ne 0) { throw "cmake configure failed ($arch / MSVC)" }
  }

  Write-Host "== build $arch =="
  & $cmake --build $build
  if ($LASTEXITCODE -ne 0) { throw "cmake build failed ($arch)" }

  $binDir = Join-Path $root "bin\$($vendorArch[$arch])"
  $artifacts = @(
    @{ file = 'crash_helper.exe'; package = 'dsh-crashlab' },
    @{ file = 'hook_host.exe'; package = 'dsh-probe' },
    @{ file = 'hook_helper.dll'; package = 'dsh-probe' },
    @{ file = 'value_hook.dll'; package = 'dsh-probe' },
    # timelab reuses probe's injector (timelab depends on probe by design), so copy the host
    # there as well; each package stays self-contained instead of reaching into another
    # package's vendor/ through relative paths.
    @{ file = 'hook_host.exe'; package = 'dsh-timelab' },
    @{ file = 'time_helper.dll'; package = 'dsh-timelab' },
    # The verify package's verify_run uses crash_helper's run mode directly (run plus
    # attribution in a single shot).
    @{ file = 'crash_helper.exe'; package = 'dsh-verify' }
  )
  foreach ($item in $artifacts) {
    $source = Join-Path $binDir $item.file
    if (-not (Test-Path $source)) { throw "Missing artifact: $source" }
    $target = Join-Path $repo "packages\$($item.package)\vendor\$($vendorArch[$arch])"
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    Copy-Item $source (Join-Path $target $item.file) -Force
    Write-Host "-> $(Join-Path $target $item.file)"
  }
}
