param(
    [ValidateSet("auto", "jaust", "James Austin")]
    [string]$MachineProfile = "auto",
    [string]$SourceDir,
    [string]$RemoteUser = "root",
    [string]$RemoteDir = "/home/root",
    [int]$ConnectTimeoutSeconds = 5,
    [string[]]$Boards
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DaemonBinary = "sgx_guardian_client"
$CliBinary = "sgx-pa-cli"

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

# Keep laptop-specific deployment defaults in one place so the operator can
# switch machines without editing the script again.
$MachineProfiles = @{
    "jaust" = @{
        AnyDeskMachine = "1 560 770 888"
        WindowsUser    = "jaust"
        SourceDir      = "C:\Users\jaust\OneDrive\Documents"
        Boards         = @(
            "192.168.1.157",
            "192.168.1.195"
        )
        SerialPorts    = @(
            "COM4",
            "COM5"
        )
    }
    "James Austin" = @{
        AnyDeskMachine = "1 251 671 333"
        WindowsUser    = "James Austin"
        SourceDir      = "C:\Users\James Austin\Documents"
        Boards         = @(
            "192.168.1.196"
        )
        SerialPorts    = @(
            "COM3"
        )
    }
}

function Resolve-MachineProfile {
    param(
        [string]$RequestedProfile,
        [hashtable]$Profiles
    )

    if ($RequestedProfile -ne "auto") {
        return $Profiles[$RequestedProfile]
    }

    $CurrentUser = $env:USERNAME
    if ($CurrentUser -and $Profiles.ContainsKey($CurrentUser)) {
        return $Profiles[$CurrentUser]
    }

    $CurrentUserProfile = $env:USERPROFILE
    foreach ($Profile in $Profiles.Values) {
        if (
            $CurrentUserProfile -and
            $Profile.SourceDir.StartsWith($CurrentUserProfile, [System.StringComparison]::OrdinalIgnoreCase)
        ) {
            return $Profile
        }
    }

    return $null
}

$SelectedMachineProfile = Resolve-MachineProfile -RequestedProfile $MachineProfile -Profiles $MachineProfiles

if (-not $PSBoundParameters.ContainsKey("SourceDir")) {
    if ($SelectedMachineProfile) {
        $SourceDir = $SelectedMachineProfile.SourceDir
    } else {
        throw "Unable to auto-detect machine profile. Use -MachineProfile 'jaust' or -MachineProfile 'James Austin', or pass -SourceDir explicitly."
    }
}

if (-not $PSBoundParameters.ContainsKey("Boards")) {
    if ($SelectedMachineProfile) {
        $Boards = [string[]]$SelectedMachineProfile.Boards
    } else {
        throw "Unable to auto-detect board list. Use -MachineProfile 'jaust' or -MachineProfile 'James Austin', or pass -Boards explicitly."
    }
}

if ($SelectedMachineProfile) {
    $SerialPortsText = ($SelectedMachineProfile.SerialPorts -join ", ")
    Write-Step "Using machine profile '$($SelectedMachineProfile.WindowsUser)' (AnyDesk: $($SelectedMachineProfile.AnyDeskMachine); Serials: $SerialPortsText)"
}

$DaemonPath = Join-Path $SourceDir $DaemonBinary
$CliPath = Join-Path $SourceDir $CliBinary

function Require-LocalFile {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    return $true
}

function Get-BinaryPlatform {
    param([string]$Path)

    $Bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($Bytes.Length -lt 20) {
        return [pscustomobject]@{
            Format      = "unknown"
            Architecture = "unknown"
            Summary     = "File is too small to inspect"
        }
    }

    if ($Bytes[0] -eq 0x4D -and $Bytes[1] -eq 0x5A) {
        return [pscustomobject]@{
            Format      = "pe"
            Architecture = "windows"
            Summary     = "Windows PE executable"
        }
    }

    if ($Bytes[0] -eq 0x7F -and $Bytes[1] -eq 0x45 -and $Bytes[2] -eq 0x4C -and $Bytes[3] -eq 0x46) {
        $MachineId = [System.BitConverter]::ToUInt16($Bytes, 18)
        $Architecture = switch ($MachineId) {
            62  { "x86-64" }
            183 { "aarch64" }
            default { "elf-machine-$MachineId" }
        }

        return [pscustomobject]@{
            Format      = "elf"
            Architecture = $Architecture
            Summary     = "Linux ELF executable ($Architecture)"
        }
    }

    return [pscustomobject]@{
        Format      = "unknown"
        Architecture = "unknown"
        Summary     = "Unrecognized binary format"
    }
}

function Require-LocalCommand {
    param([string]$CommandName)

    return [bool](Get-Command -Name $CommandName -ErrorAction SilentlyContinue)
}

function Invoke-NativeCommand {
    param(
        [string]$CommandName,
        [string[]]$Arguments,
        [switch]$SuppressOutput
    )

    $PreviousErrorActionPreference = $ErrorActionPreference
    $HasNativePreference = $false
    $PreviousNativePreference = $null

    if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
        $HasNativePreference = $true
        $PreviousNativePreference = $PSNativeCommandUseErrorActionPreference
        $script:PSNativeCommandUseErrorActionPreference = $false
    }

    $script:ErrorActionPreference = "Continue"

    try {
        if ($SuppressOutput) {
            & $CommandName @Arguments *> $null
        } else {
            & $CommandName @Arguments
        }

        return $LASTEXITCODE
    } catch {
        if ($LASTEXITCODE -is [int] -and $LASTEXITCODE -ne 0) {
            return $LASTEXITCODE
        }

        return 1
    } finally {
        $script:ErrorActionPreference = $PreviousErrorActionPreference

        if ($HasNativePreference) {
            $script:PSNativeCommandUseErrorActionPreference = $PreviousNativePreference
        }
    }
}

function Add-BoardIssue {
    param(
        [System.Collections.Generic.List[pscustomobject]]$Issues,
        [string]$Board,
        [string]$Step,
        [string]$Message,
        [string]$Command
    )

    $Issues.Add([pscustomobject]@{
        Board   = $Board
        Step    = $Step
        Message = $Message
        Command = $Command
    })
}

$SshOptions = @(
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=$ConnectTimeoutSeconds",
    "-o", "ConnectionAttempts=1"
)
$ScpOptions = @(
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=$ConnectTimeoutSeconds",
    "-o", "ConnectionAttempts=1"
)
$SshOptionText = "-o BatchMode=yes -o ConnectTimeout=$ConnectTimeoutSeconds -o ConnectionAttempts=1"
$ProbePort = 22

function Test-BoardReachable {
    param(
        [string]$BoardIp,
        [int]$Port,
        [int]$TimeoutSeconds
    )

    $Client = New-Object System.Net.Sockets.TcpClient

    try {
        $Async = $Client.BeginConnect($BoardIp, $Port, $null, $null)
        if (-not $Async.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000, $false)) {
            return $false
        }

        $null = $Client.EndConnect($Async)
        return $true
    } catch {
        return $false
    } finally {
        $Client.Close()
    }
}

$BoardIssues = [System.Collections.Generic.List[pscustomobject]]::new()
$SuccessfulBoards = [System.Collections.Generic.List[string]]::new()

if (-not (Require-LocalFile -Path $DaemonPath)) {
    Add-BoardIssue `
        -Issues $BoardIssues `
        -Board "local-machine" `
        -Step "preflight-daemon" `
        -Message "Local file not found: $DaemonPath" `
        -Command "Update -SourceDir or place $DaemonBinary at: $DaemonPath"
}

if (-not (Require-LocalFile -Path $CliPath)) {
    Add-BoardIssue `
        -Issues $BoardIssues `
        -Board "local-machine" `
        -Step "preflight-cli" `
        -Message "Local file not found: $CliPath" `
        -Command "Update -SourceDir or place $CliBinary at: $CliPath"
}

if (Require-LocalFile -Path $DaemonPath) {
    $DaemonBinaryInfo = Get-BinaryPlatform -Path $DaemonPath
    if ($DaemonBinaryInfo.Format -ne "elf" -or $DaemonBinaryInfo.Architecture -ne "aarch64") {
        Add-BoardIssue `
            -Issues $BoardIssues `
            -Board "local-machine" `
            -Step "preflight-daemon-arch" `
            -Message "$DaemonBinary is not a board-ready Linux ARM64 binary ($($DaemonBinaryInfo.Summary))" `
            -Command "Replace $DaemonBinary with the aarch64 build artifact before deploying."
    }
}

if (Require-LocalFile -Path $CliPath) {
    $CliBinaryInfo = Get-BinaryPlatform -Path $CliPath
    if ($CliBinaryInfo.Format -ne "elf" -or $CliBinaryInfo.Architecture -ne "aarch64") {
        Add-BoardIssue `
            -Issues $BoardIssues `
            -Board "local-machine" `
            -Step "preflight-cli-arch" `
            -Message "$CliBinary is not a board-ready Linux ARM64 binary ($($CliBinaryInfo.Summary))" `
            -Command "Replace $CliBinary with the aarch64 build artifact before deploying."
    }
}

if (-not (Require-LocalCommand -CommandName "ssh")) {
    Add-BoardIssue `
        -Issues $BoardIssues `
        -Board "local-machine" `
        -Step "preflight-ssh" `
        -Message "Local command not found: ssh" `
        -Command "Install OpenSSH client or run: Get-WindowsCapability -Online | ? Name -like 'OpenSSH.Client*'"
}

if (-not (Require-LocalCommand -CommandName "scp")) {
    Add-BoardIssue `
        -Issues $BoardIssues `
        -Board "local-machine" `
        -Step "preflight-scp" `
        -Message "Local command not found: scp" `
        -Command "Install OpenSSH client or run: Get-WindowsCapability -Online | ? Name -like 'OpenSSH.Client*'"
}

if ($BoardIssues.Count -eq 0) {
    foreach ($Board in $Boards) {
        $Target = "$RemoteUser@$Board"
        $BoardHasIssue = $false
        $ProbeCommand = "ssh $SshOptionText $Target 'exit 0'"
        $CleanupCommand = "ssh $SshOptionText $Target 'rm -rf $RemoteDir/$DaemonBinary $RemoteDir/$CliBinary /var/lib/sgx-guardian'"
        $CopyDaemonCommand = "scp -o BatchMode=yes -o ConnectTimeout=$ConnectTimeoutSeconds -o ConnectionAttempts=1 `"$DaemonPath`" `"${Target}:$RemoteDir/`""
        $CopyCliCommand = "scp -o BatchMode=yes -o ConnectTimeout=$ConnectTimeoutSeconds -o ConnectionAttempts=1 `"$CliPath`" `"${Target}:$RemoteDir/`""
        $ChmodCommand = "ssh $SshOptionText $Target 'chmod +x $RemoteDir/$DaemonBinary $RemoteDir/$CliBinary'"

        Write-Step "Checking board availability on $Board"
        if (-not (Test-BoardReachable -BoardIp $Board -Port $ProbePort -TimeoutSeconds $ConnectTimeoutSeconds)) {
            Add-BoardIssue -Issues $BoardIssues -Board $Board -Step "reachability" -Message "Board appears offline or SSH is unreachable. Skipping remaining steps." -Command $ProbeCommand
            continue
        }

        Write-Step "Cleaning old binaries and state on $Board"
        $CleanupExitCode = Invoke-NativeCommand -CommandName "ssh" -Arguments ($SshOptions + @($Target, "rm -rf $RemoteDir/$DaemonBinary $RemoteDir/$CliBinary /var/lib/sgx-guardian")) -SuppressOutput
        if ($CleanupExitCode -ne 0) {
            $BoardHasIssue = $true
            Add-BoardIssue -Issues $BoardIssues -Board $Board -Step "cleanup" -Message "Remote cleanup failed" -Command $CleanupCommand
        }

        Write-Step "Copying $DaemonBinary to $Board"
        $CopyDaemonExitCode = Invoke-NativeCommand -CommandName "scp" -Arguments ($ScpOptions + @($DaemonPath, "${Target}:$RemoteDir/")) -SuppressOutput
        if ($CopyDaemonExitCode -ne 0) {
            $BoardHasIssue = $true
            Add-BoardIssue -Issues $BoardIssues -Board $Board -Step "copy-daemon" -Message "Failed to copy $DaemonBinary" -Command $CopyDaemonCommand
        }

        Write-Step "Copying $CliBinary to $Board"
        $CopyCliExitCode = Invoke-NativeCommand -CommandName "scp" -Arguments ($ScpOptions + @($CliPath, "${Target}:$RemoteDir/")) -SuppressOutput
        if ($CopyCliExitCode -ne 0) {
            $BoardHasIssue = $true
            Add-BoardIssue -Issues $BoardIssues -Board $Board -Step "copy-cli" -Message "Failed to copy $CliBinary" -Command $CopyCliCommand
        }

        Write-Step "Making binaries executable on $Board"
        $ChmodExitCode = Invoke-NativeCommand -CommandName "ssh" -Arguments ($SshOptions + @($Target, "chmod +x $RemoteDir/$DaemonBinary $RemoteDir/$CliBinary")) -SuppressOutput
        if ($ChmodExitCode -ne 0) {
            $BoardHasIssue = $true
            Add-BoardIssue -Issues $BoardIssues -Board $Board -Step "chmod" -Message "chmod failed" -Command $ChmodCommand
        }

        if (-not $BoardHasIssue) {
            $SuccessfulBoards.Add($Board)
        }
    }
}

Write-Host ""
Write-Host "Deployment summary" -ForegroundColor Yellow

if ($SuccessfulBoards.Count -gt 0) {
    Write-Host "Successful boards:" -ForegroundColor Green
    foreach ($Board in $SuccessfulBoards) {
        Write-Host "  - $Board"
    }
}

if ($BoardIssues.Count -gt 0) {
    Write-Host "Boards with issues:" -ForegroundColor Red
    foreach ($Issue in $BoardIssues) {
        Write-Host "  - $($Issue.Board) [$($Issue.Step)]: $($Issue.Message)"
        Write-Host "    Manual retry/action: $($Issue.Command)"
    }
    Write-Host "Manual check required for the boards listed above." -ForegroundColor Red
} else {
    Write-Step "Binary deployment completed successfully on all boards."
}
