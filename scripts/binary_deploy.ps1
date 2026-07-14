param(
    [string]$SourceDir = "/Users/Stores/Documents",
    [string]$RemoteUser = "root",
    [string]$RemoteDir = "/home/root",
    [int]$ConnectTimeoutSeconds = 5,
    [string[]]$Boards = @(
        "192.168.50.103",
        "192.168.50.115",
        "192.168.50.248"
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DaemonBinary = "sgx_guardian_client"
$CliBinary = "sgx-pa-cli"
$DaemonPath = Join-Path $SourceDir $DaemonBinary
$CliPath = Join-Path $SourceDir $CliBinary

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Require-LocalFile {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    return $true
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
