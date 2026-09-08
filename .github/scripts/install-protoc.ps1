param(
    [string]$Version = "35.1",
    [string]$InstallDirectory = (Join-Path ($env:RUNNER_TEMP ?? $env:TEMP) "protoc-$Version")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ProtocArtifact {
    param([string]$RequestedVersion)

    if ($RequestedVersion -ne "35.1") {
        throw "unsupported protoc version: $RequestedVersion"
    }

    [pscustomobject]@{
        ArchiveName = "protoc-35.1-win64.zip"
        DownloadUrl = "https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-win64.zip"
        Sha256 = "5d3ff218d7d91eea95f7569bcb5a98f3030f8996d44151279d9772edcff76082"
    }
}

function Assert-Sha256 {
    param(
        [string]$Path,
        [string]$ExpectedSha256
    )

    $actualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $ExpectedSha256.ToLowerInvariant()) {
        throw "checksum mismatch for $Path"
    }
}

function Install-Protoc {
    param(
        [string]$RequestedVersion,
        [string]$Destination
    )

    $artifact = Get-ProtocArtifact $RequestedVersion
    $archivePath = Join-Path ($env:RUNNER_TEMP ?? $env:TEMP) $artifact.ArchiveName

    Invoke-WebRequest -Uri $artifact.DownloadUrl -OutFile $archivePath
    Assert-Sha256 $archivePath $artifact.Sha256
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Expand-Archive -LiteralPath $archivePath -DestinationPath $Destination -Force

    $protoc = Join-Path $Destination "bin\protoc.exe"
    $actualVersion = & $protoc --version
    if ($actualVersion -ne "libprotoc $RequestedVersion") {
        throw "unexpected protoc version: $actualVersion"
    }

    if ($env:GITHUB_PATH) {
        (Join-Path $Destination "bin") | Out-File -FilePath $env:GITHUB_PATH -Encoding utf8 -Append
    }

    Write-Output "Installed $actualVersion from verified official release."
}

if ($MyInvocation.InvocationName -ne ".") {
    Install-Protoc $Version $InstallDirectory
}
