Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. "$PSScriptRoot/install-protoc.ps1"

$artifact = Get-ProtocArtifact "35.1"
if ($artifact.ArchiveName -ne "protoc-35.1-win64.zip") {
    throw "unexpected Windows protoc archive"
}
if ($artifact.Sha256 -ne "5d3ff218d7d91eea95f7569bcb5a98f3030f8996d44151279d9772edcff76082") {
    throw "unexpected Windows protoc checksum"
}

$fixture = New-TemporaryFile
try {
    Set-Content -LiteralPath $fixture -Value "protoc fixture" -NoNewline
    $fixtureSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $fixture).Hash
    Assert-Sha256 $fixture $fixtureSha256

    Add-Content -LiteralPath $fixture -Value "tampered"
    try {
        Assert-Sha256 $fixture $fixtureSha256
        throw "checksum verification accepted a modified archive"
    } catch {
        if ($_.Exception.Message -eq "checksum verification accepted a modified archive") {
            throw
        }
    }
} finally {
    Remove-Item -LiteralPath $fixture -Force
}

try {
    Get-ProtocArtifact "35.0" | Out-Null
    throw "unsupported protoc version was accepted"
} catch {
    if ($_.Exception.Message -eq "unsupported protoc version was accepted") {
        throw
    }
}

Write-Output "Windows protoc installer tests passed"
