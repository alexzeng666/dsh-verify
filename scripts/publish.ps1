# Publish five packages: quota -> crashlab -> probe -> timelab -> verify
#
# Local development uses file:/workspace: dependencies (the profile has no workspace), but npm
# does not convert these protocols, so anything published as-is cannot be installed by anyone.
# So rewrite them to concrete versions before publishing, and restore from .bak afterwards
# (on both success and failure).
#
#   pwsh scripts/publish.ps1 -DryRun    # verify only: rewrite -> npm pack -> inspect package.json inside the tarball -> restore
#   pwsh scripts/publish.ps1            # real publish
#
# dsh-verify-contract is private:true, so npm publish would reject it; the script skips it.
param(
  [switch]$DryRun,
  [string]$Tag = 'latest'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$packages = @('dsh-quota', 'dsh-crashlab', 'dsh-probe', 'dsh-timelab', 'dsh-verify')
$manifestPaths = @($packages + 'dsh-verify-contract' | ForEach-Object { Join-Path $root "packages\$_\package.json" })

# npm only auto-includes a LICENSE that sits inside the package directory itself; the repo-root
# copy does not make it into the tarball. Copy it in for the duration of the run, remove it after.
$licensePaths = $packages | ForEach-Object { Join-Path $root "packages\$_\LICENSE" }
foreach ($path in $licensePaths) { Copy-Item (Join-Path $root 'LICENSE') $path -Force }

# Back up
foreach ($path in $manifestPaths) { Copy-Item $path "$path.bak" -Force }

$work = Join-Path $root '.publish-tmp'
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Force $work | Out-Null

try {
  & node (Join-Path $PSScriptRoot 'rewrite-deps.mjs')
  if ($LASTEXITCODE -ne 0) { throw 'rewrite-deps failed' }

  & node (Join-Path $PSScriptRoot 'rewrite-deps.mjs') --check
  if ($LASTEXITCODE -ne 0) { throw 'some local dependencies are still not rewritten' }

  foreach ($name in $packages) {
    Push-Location (Join-Path $root "packages\$name")
    try {
      if ($DryRun) {
        $tgz = (npm pack --silent --pack-destination $work) 2>$null | Select-Object -Last 1
        if (-not $tgz) { throw "${name}: npm pack produced no tarball" }
        $inside = & tar -xOf (Join-Path $work $tgz) 'package/package.json'
        $manifest = $inside | ConvertFrom-Json
        $bad = @()
        foreach ($field in 'dependencies', 'peerDependencies', 'optionalDependencies') {
          $deps = $manifest.$field
          if (-not $deps) { continue }
          foreach ($prop in $deps.PSObject.Properties) {
            if ($prop.Value -match '^(file:|link:|workspace:)') { $bad += "$field.$($prop.Name)=$($prop.Value)" }
          }
        }
        if ($bad.Count -gt 0) { throw "${name}: tarball still contains local dependencies -> $($bad -join ', ')" }
        $entries = & tar -tzf (Join-Path $work $tgz)
        if (-not ($entries -contains 'package/LICENSE')) { throw "${name}: tarball has no LICENSE file" }
        $depText = if ($manifest.dependencies) {
          ($manifest.dependencies.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', '
        } else { '(none)' }
        Write-Host "[ok] $name -> $tgz | dependencies: $depText"
      } else {
        Write-Host "[publish] $name"
        # Scoped packages are private (restricted) by default, so --access public must be explicit;
        # the local npm default registry is often set to a domestic mirror (read-only), so publishing
        # must explicitly target the official registry.
        npm publish --tag $Tag --access public --registry https://registry.npmjs.org
        if ($LASTEXITCODE -ne 0) { throw "$name publish failed" }
      }
    } finally {
      Pop-Location
    }
  }

  Write-Host ($DryRun ? '[done] dry-run passed, ready for a real publish' : '[done] all five packages published')
} finally {
  # Restore regardless of outcome, so rewritten package.json files are not left in the workspace
  foreach ($path in $manifestPaths) {
    if (Test-Path "$path.bak") { Move-Item "$path.bak" $path -Force }
  }
  foreach ($path in $licensePaths) {
    if (Test-Path $path) { Remove-Item $path -Force }
  }
  if (Test-Path $work) { Remove-Item $work -Recurse -Force }
  Write-Host '[restore] package.json files restored, copied LICENSE files removed'
}
