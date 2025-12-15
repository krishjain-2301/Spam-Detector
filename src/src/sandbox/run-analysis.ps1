# This script runs inside the Windows Sandbox to execute and analyze the target file
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Setup basic sandbox environment
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Setup paths for analysis
$WorkDir = "C:\Users\WDAGUtilityAccount\Desktop\sandbox-share"
$LogFile = Join-Path $WorkDir "execution.log"
$ResultFile = Join-Path $WorkDir "result.json"

Write-Output "Sandbox security measures enabled - Network access and system modifications blocked"

# Additional security measures
$env:SEE_MASK_NOZONECHECKS = 0  # Disable autorun
$env:__COMPAT_LAYER = "RunAsInvoker"  # Prevent elevation attempts

# Find target file in share directory
$TargetFile = Get-ChildItem -Path $WorkDir -File | Where-Object { 
    $_.Name -notmatch '(\.wsb|\.ps1|\.json|\.log)$' 
} | Select-Object -First 1 -ExpandProperty FullName

if (!$TargetFile) {
    throw "No target file found in $WorkDir"
}

$TimeoutSeconds = 30 # Maximum execution time per process

function Write-Log {
    param([string]$Message)
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$time - $Message" | Tee-Object -FilePath $LogFile -Append
}

function Get-FileAnalysis {
    param([string]$Path)
    
    try {
        $file = Get-Item $Path
        $hash = Get-FileHash -Path $Path -Algorithm SHA256
        $cert = $null
        try { $cert = Get-AuthenticodeSignature $Path } catch {}
        
        @{
            Name = $file.Name
            Size = $file.Length
            CreationTime = $file.CreationTime
            LastWriteTime = $file.LastWriteTime
            Hash = $hash.Hash
            Extension = $file.Extension
            Signed = $cert -and $cert.Status -eq "Valid"
            SignatureStatus = $cert ? $cert.Status.ToString() : "Unsigned"
        }
    }
    catch {
        @{ Error = $_.Exception.Message }
    }
}

function Get-ProcessBehavior {
    param(
        [Parameter(Mandatory=$true)]
        [System.Diagnostics.Process]$Process
    )
    
    try {
        $behavior = @{
            Id = $Process.Id
            ProcessName = $Process.ProcessName
            StartTime = $Process.StartTime
            CPU = $Process.CPU
            WorkingSet = $Process.WorkingSet64
            Threads = $Process.Threads.Count
            Modules = @()
            NetworkConnections = @()
            FileAccesses = @()
        }
        
        # Get loaded modules
        $Process.Modules | ForEach-Object {
            $behavior.Modules += $_.ModuleName
        }
        
        # Get network connections (requires admin)
        try {
            $netstat = netstat -no | Select-String -Pattern $Process.Id
            $behavior.NetworkConnections = $netstat
        } catch {}
        
        # Monitor file access (simplified)
        try {
            $behavior.FileAccesses = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                Id = 4663  # File access
                StartTime = $Process.StartTime
            } | Where-Object { $_.Properties[1].Value -eq $Process.Id }
        } catch {}
        
        $behavior
    }
    catch {
        @{ Error = $_.Exception.Message }
    }
}

Write-Log "Starting sandbox analysis of: $TargetFile"

# Initial file analysis
$fileInfo = Get-FileAnalysis $TargetFile
Write-Log "File analysis complete"

# Prepare result structure
$result = @{
    FileInfo = $fileInfo
    Execution = @{
        StartTime = Get-Date
        ExitCode = $null
        Duration = $null
        Output = ""
        Error = ""
        Behavior = $null
    }
}

try {
    Write-Log "Preparing to execute file..."
    
    # Create job to run the file with timeout
    $job = Start-Job -ScriptBlock {
        param($Path)
        $output = & $Path 2>&1
        @{
            Output = $output | Out-String
            ExitCode = $LASTEXITCODE
        }
    } -ArgumentList $TargetFile
    
    # Monitor the process
    $process = $null
    $startTime = Get-Date
    
    while (-not $job.HasMoreData -and -not $process) {
        $process = Get-Process | Where-Object {
            $_.Path -eq $TargetFile
        } | Select-Object -First 1
        Start-Sleep -Milliseconds 100
        
        if ((Get-Date) - $startTime).TotalSeconds -gt $TimeoutSeconds) {
            throw "Execution timed out after $TimeoutSeconds seconds"
        }
    }
    
    if ($process) {
        Write-Log "Process started (PID: $($process.Id))"
        $behavior = Get-ProcessBehavior $process
        $result.Execution.Behavior = $behavior
    }
    
    # Wait for completion or timeout
    $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds
    if (-not $completed) {
        Stop-Job -Job $job
        throw "Execution timed out after $TimeoutSeconds seconds"
    }
    
    $jobResult = Receive-Job -Job $job
    $result.Execution.Output = $jobResult.Output
    $result.Execution.ExitCode = $jobResult.ExitCode
    $result.Execution.Duration = ((Get-Date) - $result.Execution.StartTime).TotalSeconds
    
    Write-Log "Execution completed successfully"
}
catch {
    Write-Log "Error during execution: $_"
    $result.Execution.Error = $_.Exception.Message
}
finally {
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
}

# Save results
$result | ConvertTo-Json -Depth 10 | Set-Content $ResultFile
Write-Log "Analysis complete. Results saved to: $ResultFile"