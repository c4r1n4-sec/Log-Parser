[CmdletBinding()]
param(
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Command,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    Write-Host $Description
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE"
    }
}

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvDir = Join-Path $RepoRoot ".venv"
$Python = Join-Path $VenvDir "Scripts\python.exe"
$PyInstallerSpec = Join-Path $RepoRoot "packaging\pyinstaller\drop_target.spec"
$DistRoot = Join-Path $RepoRoot "dist"
$PortableDir = Join-Path $DistRoot "TDSYNNEX-CB-LogParser"
$PortableZip = Join-Path $DistRoot "TDSYNNEX-CB-LogParser-portable.zip"

Write-Host "TDSYNNEX Carbon Black Log Parser portable build"
Write-Host "Repository: $RepoRoot"

Push-Location $RepoRoot
try {
    if (-not (Test-Path $Python)) {
        Invoke-Checked { python -m venv $VenvDir } "Creating virtual environment: $VenvDir"
    }

    Invoke-Checked { & $Python -m pip install --upgrade pip } "Upgrading pip"
    Invoke-Checked {
        & $Python -m pip install -r (Join-Path $RepoRoot "requirements.txt")
    } "Installing package requirements"

    & $Python -c "import PyInstaller" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Invoke-Checked { & $Python -m pip install pyinstaller } "Installing PyInstaller"
    }

    & $Python -c "import pytest" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Invoke-Checked { & $Python -m pip install pytest } "Installing pytest for build validation"
    }

    if (-not $SkipTests) {
        Invoke-Checked { & $Python -m pytest -q } "Running tests"
    }

    if (Test-Path $PortableDir) {
        Remove-Item $PortableDir -Recurse -Force
    }

    Invoke-Checked {
        & $Python -m PyInstaller --clean --noconfirm $PyInstallerSpec
    } "Running PyInstaller one-folder build"

    if (-not (Test-Path $PortableDir)) {
        throw "Expected portable folder was not created: $PortableDir"
    }

    $ExpectedExe = Join-Path $PortableDir "TDSYNNEX-CB-LogParser.exe"
    if (-not (Test-Path $ExpectedExe)) {
        throw "Expected portable EXE was not created: $ExpectedExe"
    }

    Write-Host "Ensuring portable root handoff and data files are present"
    Copy-Item -Path (Join-Path $RepoRoot "DROP-CUSTOMER-LOGS-HERE.bat") -Destination $PortableDir -Force
    Copy-Item -Path (Join-Path $RepoRoot "README-DROP-MODE.txt") -Destination $PortableDir -Force

    $ConfigDir = Join-Path $PortableDir "config"
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    Copy-Item -Path (Join-Path $RepoRoot "app\config\defaults.json") -Destination $ConfigDir -Force

    foreach ($AssetDir in @("rules", "templates", "tools")) {
        $SourceDir = Join-Path $RepoRoot $AssetDir
        $TargetDir = Join-Path $PortableDir $AssetDir
        if (Test-Path $TargetDir) {
            Remove-Item $TargetDir -Recurse -Force
        }
        Copy-Item -Path $SourceDir -Destination $TargetDir -Recurse -Force
    }

    $OutputDir = Join-Path $PortableDir "output"
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

    $ExpectedPaths = @(
        "TDSYNNEX-CB-LogParser.exe",
        "DROP-CUSTOMER-LOGS-HERE.bat",
        "README-DROP-MODE.txt",
        "config\defaults.json",
        "rules",
        "templates",
        "tools",
        "output",
        "_internal"
    )
    foreach ($RelativePath in $ExpectedPaths) {
        $FullPath = Join-Path $PortableDir $RelativePath
        if (-not (Test-Path $FullPath)) {
            throw "Portable package is missing required path: $FullPath"
        }
    }

    $InternalExe = Join-Path $PortableDir "_internal\TDSYNNEX-CB-LogParser.exe"
    if (Test-Path $InternalExe) {
        throw "Portable EXE must be at portable root, not under _internal: $InternalExe"
    }

    if (Test-Path $PortableZip) {
        Remove-Item $PortableZip -Force
    }

    Write-Host "Creating portable ZIP: $PortableZip"
    Compress-Archive -Path $PortableDir -DestinationPath $PortableZip -Force

    Write-Host "Portable folder: $PortableDir"
    Write-Host "Portable ZIP: $PortableZip"
}
finally {
    Pop-Location
}
