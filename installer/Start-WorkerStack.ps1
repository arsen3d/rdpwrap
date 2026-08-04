<#
.SYNOPSIS
    Logon script for the RDP worker account: brings up Docker Desktop, then a
    k3s cluster running in Docker via k3d.

.DESCRIPTION
    Run by the scheduled task that Install-RDPWrap.ps1 registers, inside the
    worker's own interactive session. It must run there rather than at
    provisioning time: Docker Desktop's engine is per-user, so no cluster can be
    created from an elevated installer context.

    Safe to run repeatedly. An existing cluster is started rather than recreated.

.PARAMETER ClusterName
    k3d cluster to start or create. When empty, only Docker Desktop is started.

.PARAMETER DockerTimeoutSeconds
    How long to wait for the Docker engine before giving up.
#>
[CmdletBinding()]
param(
    [string] $ClusterName = 'worker',
    [int]    $DockerTimeoutSeconds = 300,
    [string] $LogPath = (Join-Path $env:LOCALAPPDATA 'rdpwrap-worker-stack.log')
)

$ErrorActionPreference = 'Stop'

function Write-Log {
    param([string] $Message, [string] $Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    try { Add-Content -Path $LogPath -Value $line -Encoding utf8 } catch { }
}

# Native tools write progress to stderr; with $ErrorActionPreference = 'Stop'
# Windows PowerShell would turn that into a terminating error regardless of the
# exit code. Judge success by exit code instead.
function Invoke-NativeCapture {
    param([Parameter(Mandatory)][scriptblock] $Command)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $Command 2>&1
        [pscustomobject]@{ Output = $out; ExitCode = $LASTEXITCODE }
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Resolve-Tool {
    param([string] $Name, [string[]] $Fallbacks)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($f in $Fallbacks) { if ($f -and (Test-Path $f)) { return $f } }
    return $null
}

Write-Log "=== worker stack startup ==="

# ---------------------------------------------------------------- Docker ----
$dockerDesktop = Resolve-Tool -Name 'Docker Desktop.exe' -Fallbacks @(
    (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe')
)
if (-not $dockerDesktop) { Write-Log "Docker Desktop not found; nothing to start." 'ERROR'; exit 1 }

if (-not (Get-Process 'Docker Desktop' -ErrorAction SilentlyContinue)) {
    Write-Log "Starting Docker Desktop..."
    Start-Process -FilePath $dockerDesktop
} else {
    Write-Log "Docker Desktop is already running."
}

$docker = Resolve-Tool -Name 'docker' -Fallbacks @(
    (Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe')
)
if (-not $docker) { Write-Log "docker CLI not found." 'ERROR'; exit 1 }

Write-Log "Waiting up to $DockerTimeoutSeconds s for the Docker engine..."
$deadline = (Get-Date).AddSeconds($DockerTimeoutSeconds)
$engineUp = $false
while ((Get-Date) -lt $deadline) {
    if ((Invoke-NativeCapture { & $docker info --format '{{.ServerVersion}}' }).ExitCode -eq 0) {
        $engineUp = $true
        break
    }
    Start-Sleep -Seconds 5
}
if (-not $engineUp) { Write-Log "Docker engine did not become ready in time." 'ERROR'; exit 1 }
Write-Log "Docker engine is ready."

# Confirm the engine really belongs to this account. WSL distributions are
# registered per Windows user under HKCU, and Docker Desktop keeps its distro
# and data VHDX under the user's own LOCALAPPDATA, so a correctly isolated
# worker sees a docker-desktop distro rooted in its own profile. Logging it
# turns 'k3s runs in worker's context' into something checkable after the fact.
function Write-DockerScope {
    $lxss = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
    if (-not (Test-Path $lxss)) { Write-Log "No per-user WSL registrations found." 'WARN'; return }

    $distro = Get-ChildItem $lxss -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ItemProperty $_.PSPath } |
        Where-Object { $_.DistributionName -eq 'docker-desktop' } |
        Select-Object -First 1

    if (-not $distro) { Write-Log "No docker-desktop WSL distro registered for $env:USERNAME." 'WARN'; return }

    $base = $distro.BasePath -replace '^\\\\\?\\', ''
    Write-Log "Docker Desktop distro for $($env:USERNAME): $base"
    if ($base -like "$env:LOCALAPPDATA*") {
        Write-Log "Engine storage is inside this account's profile; the cluster will be private to $env:USERNAME."
    } else {
        Write-Log "Engine storage is outside this account's profile ($base); the cluster may be shared with another user." 'WARN'
    }
}
Write-DockerScope

if (-not $ClusterName) { Write-Log "No cluster requested; done."; exit 0 }

# ------------------------------------------------------------------- k3s ----
# k3d runs k3s inside Docker containers. Using k3d rather than a hand-rolled
# 'docker run rancher/k3s' avoids having to manage privileged mode, cgroup
# mounts and the API server load balancer by hand.
$k3d = Resolve-Tool -Name 'k3d' -Fallbacks @(
    (Join-Path $env:ProgramFiles 'WinGet\Links\k3d.exe'),
    (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links\k3d.exe')
)
if (-not $k3d) { Write-Log "k3d not found; re-run the installer with -EnsureK3s." 'ERROR'; exit 1 }

$exists = $false
$list = Invoke-NativeCapture { & $k3d cluster list -o json }
if ($list.ExitCode -eq 0) {
    try {
        $clusters = ($list.Output -join '') | ConvertFrom-Json
        $exists = @($clusters | Where-Object { $_.name -eq $ClusterName }).Count -gt 0
    } catch {
        Write-Log "Could not parse 'k3d cluster list' output; assuming the cluster is absent." 'WARN'
    }
}

if ($exists) {
    Write-Log "Starting existing cluster '$ClusterName'..."
    $r = Invoke-NativeCapture { & $k3d cluster start $ClusterName }
} else {
    # First run pulls the rancher/k3s image, so this can take several minutes.
    Write-Log "Creating cluster '$ClusterName' (first run pulls the k3s image; this may take a while)..."
    $r = Invoke-NativeCapture { & $k3d cluster create $ClusterName --wait }
}
$r.Output | ForEach-Object { Write-Log $_ }

if ($r.ExitCode -ne 0) { Write-Log "k3d failed with exit code $($r.ExitCode)." 'ERROR'; exit 1 }
Write-Log "Cluster '$ClusterName' is up."

$kubectl = Resolve-Tool -Name 'kubectl' -Fallbacks @(
    (Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\kubectl.exe')
)
if ($kubectl) {
    $nodes = Invoke-NativeCapture { & $kubectl --context "k3d-$ClusterName" get nodes }
    $nodes.Output | ForEach-Object { Write-Log $_ }
}

Write-Log "=== worker stack ready ==="
