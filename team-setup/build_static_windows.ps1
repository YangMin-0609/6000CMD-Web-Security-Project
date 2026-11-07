param(
    [Parameter(Mandatory = $true)]
    [string]$ProjectRoot,

    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Resolve-Path -LiteralPath $ProjectRoot).Path
$packageJson = Join-Path $root 'package.json'
$modules = Join-Path $root 'node_modules'

if (-not (Test-Path -LiteralPath $packageJson)) {
    throw "package.json was not found under $root. Run this from the Django project root."
}
if (-not (Test-Path -LiteralPath $modules)) {
    throw "node_modules was not found. Run 'corepack yarn install' in the project root first."
}

$vendorRoot = if ($OutputRoot) {
    $OutputRoot
} else {
    Join-Path $root 'src/helpdesk/static/helpdesk/vendor'
}
New-Item -ItemType Directory -Force -Path $vendorRoot | Out-Null

function Copy-Contents {
    param([string]$Source, [string]$Destination)

    if (-not (Test-Path -LiteralPath $Source)) { return $false }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Get-ChildItem -LiteralPath $Source -Force | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $Destination -Recurse -Force
    }
    return $true
}

$dependencies = (Get-Content -LiteralPath $packageJson -Raw | ConvertFrom-Json).dependencies.PSObject.Properties.Name
foreach ($name in $dependencies) {
    $source = Join-Path $modules $name
    if (-not (Test-Path -LiteralPath $source)) {
        throw "Missing node_modules/$name. Run 'corepack yarn install' first."
    }

    if ($name -like 'datatables*') {
        foreach ($folder in @('js', 'css', 'images')) {
            $sourceFolder = Join-Path $source $folder
            $destinationFolder = Join-Path (Join-Path $vendorRoot 'datatables') $folder
            $null = Copy-Contents -Source $sourceFolder -Destination $destinationFolder
        }
        continue
    }

    $destinationName = if ($name -eq 'metismenu') { 'metisMenu' } else { $name }
    $destination = Join-Path $vendorRoot $destinationName
    $dist = Join-Path $source 'dist'

    if (Test-Path -LiteralPath $dist) {
        if ($name -eq 'jquery-ui') {
            $null = Copy-Contents -Source (Join-Path $dist 'themes/base') -Destination $destination
        }
        $null = Copy-Contents -Source $dist -Destination $destination
    } elseif (Test-Path -LiteralPath (Join-Path $source 'umd')) {
        $null = Copy-Contents -Source (Join-Path $source 'umd') -Destination (Join-Path $destination 'umd')
    } else {
        foreach ($folder in @('js', 'css', 'webfonts')) {
            $null = Copy-Contents -Source (Join-Path $source $folder) -Destination (Join-Path $destination $folder)
        }
        New-Item -ItemType Directory -Force -Path $destination | Out-Null
        Get-ChildItem -LiteralPath $source -File | Where-Object {
            $_.Name -like '*.min.js' -or $_.Extension -eq '.css'
        } | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName -Destination $destination -Force
        }
    }
}

$requiredFiles = @(
    'bootstrap/css/bootstrap.min.css',
    'bootstrap/js/bootstrap.bundle.min.js',
    'fontawesome-free/css/all.min.css',
    'jquery/jquery.min.js',
    'jquery-ui/jquery-ui.min.css',
    'datatables/js/dataTables.min.js',
    'datatables/css/dataTables.bootstrap5.css',
    'datatables/js/dataTables.buttons.min.js',
    'metisMenu/metisMenu.min.js'
)

$missing = @($requiredFiles | Where-Object {
    -not (Test-Path -LiteralPath (Join-Path $vendorRoot $_))
})
if ($missing.Count -gt 0) {
    throw "Static build incomplete. Missing: $($missing -join ', ')"
}

Write-Host "Static vendor assets are ready in $vendorRoot"
