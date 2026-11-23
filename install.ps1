$ErrorActionPreference = "Stop"

$Repo = "Khoinguyen002/ssh-fleet"
$InstallDir = Join-Path $HOME ".local\bin"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$Target = Join-Path $InstallDir "sf.exe"
$Url = "https://github.com/$Repo/releases/latest/download/sf-windows-amd64.exe"

Write-Host "Downloading sf-windows-amd64.exe from $Url..."
Invoke-WebRequest -Uri $Url -OutFile $Target -UseBasicParsing

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $UserPath) { $UserPath = "" }
if ($UserPath -notlike "*$InstallDir*") {
    $NewPath = if ($UserPath.TrimEnd(";") -eq "") { $InstallDir } else { "$($UserPath.TrimEnd(';'));$InstallDir" }
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    $env:Path = "$env:Path;$InstallDir"
}

Write-Host "Installed sf.exe -> $Target"

if ($env:SF_HUB -and $env:SF_TOKEN) {
    $joinArgs = @("join", $env:SF_HUB, $env:SF_TOKEN)
    if ($env:SF_NAME) {
        $joinArgs += @("--name", $env:SF_NAME)
    }
    & $Target @joinArgs
} else {
    Write-Host "Run: sf.exe join <HUB_URL> <TOKEN> [--name DEVICE_NAME]"
}
