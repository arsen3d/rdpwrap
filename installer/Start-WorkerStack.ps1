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
    [string] $LogPath = (Join-Path $env:LOCALAPPDATA 'rdpwrap-worker-stack.log'),

    # Hello World chart. Fetched from the repository archive rather than a Helm
    # repository, so the chart lives with the code that deploys it.
    [string] $ChartArchiveUrl = 'https://github.com/arsen3d/rdpwrap/archive/refs/heads/master.zip',
    [string] $ChartSubPath    = 'charts/hello-world',
    [string] $ReleaseName     = 'hello-world',
    [int]    $HostPort        = 8080,
    [int]    $NodePort        = 30080,
    [int]    $ApiPort         = 6445,
    [switch] $SkipChart,
    [switch] $NoBrowser
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
    # The port mapping has to be declared here: k3d fixes published ports when
    # the cluster is created, and it cannot be added to a running cluster.
    Write-Log "Creating cluster '$ClusterName' with $HostPort->$NodePort published (first run pulls the k3s image; this may take a while)..."
    # --api-port is required, not optional: without it k3d leaves 6443 exposed
    # but unpublished and writes a kubeconfig pointing at host.docker.internal
    # on a port nothing ever bound, so every kubectl and helm call times out.
    $r = Invoke-NativeCapture {
        & $k3d cluster create $ClusterName `
            --api-port "127.0.0.1:$ApiPort" `
            -p "${HostPort}:${NodePort}@loadbalancer" --wait
    }
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

if ($SkipChart) { Write-Log "Chart deployment skipped."; Write-Log "=== worker stack ready ==="; exit 0 }

# ------------------------------------------------------------------ helm ----
$helm = Resolve-Tool -Name 'helm' -Fallbacks @(
    (Join-Path $env:ProgramFiles 'WinGet\Links\helm.exe'),
    (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links\helm.exe')
)
if (-not $helm) { Write-Log "helm not found; re-run the installer with -EnsureK3s." 'ERROR'; exit 1 }

# The chart is pulled straight from the GitHub repository archive. This keeps
# one source of truth and needs no chart registry or gh-pages branch.
$work = Join-Path $env:TEMP "rdpwrap-chart-$PID"
$zip  = Join-Path $env:TEMP "rdpwrap-chart-$PID.zip"
try {
    Write-Log "Downloading chart from $ChartArchiveUrl ..."
    $progress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'   # ~10x faster for Invoke-WebRequest
    try {
        Invoke-WebRequest -Uri $ChartArchiveUrl -OutFile $zip -UseBasicParsing
    } finally {
        $ProgressPreference = $progress
    }

    if (Test-Path $work) { Remove-Item $work -Recurse -Force }
    Expand-Archive -Path $zip -DestinationPath $work -Force

    # GitHub archives wrap everything in a <repo>-<ref> directory whose name
    # depends on the branch, so discover it rather than hard-coding it.
    $root = Get-ChildItem $work -Directory | Select-Object -First 1
    if (-not $root) { throw "Downloaded archive contained no directory." }

    $chartPath = Join-Path $root.FullName $ChartSubPath
    if (-not (Test-Path (Join-Path $chartPath 'Chart.yaml'))) {
        throw "No Chart.yaml under '$chartPath'."
    }
    Write-Log "Chart located at $chartPath"

    Write-Log "Installing release '$ReleaseName'..."
    $r = Invoke-NativeCapture {
        & $helm upgrade --install $ReleaseName $chartPath `
            --kube-context "k3d-$ClusterName" `
            --set "service.nodePort=$NodePort" `
            --wait --timeout 5m
    }
    $r.Output | ForEach-Object { Write-Log $_ }
    if ($r.ExitCode -ne 0) { Write-Log "helm failed with exit code $($r.ExitCode)." 'ERROR'; exit 1 }
    Write-Log "Release '$ReleaseName' installed."
} finally {
    Remove-Item $zip  -Force -ErrorAction SilentlyContinue
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

# --------------------------------------------------------------- browser ----
# 127.0.0.1, not localhost: 'localhost' resolves to ::1 first on Windows, and
# Docker Desktop's IPv6 publication does not carry traffic, so the request hangs
# until it times out even though the service is serving perfectly on IPv4.
$url = "http://127.0.0.1:$HostPort"
Write-Log "Waiting for $url to serve..."
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        if ((Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5).StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch { Start-Sleep -Seconds 2 }
}

if (-not $ready) {
    Write-Log "$url did not respond. If the cluster predates this script it may lack the ${HostPort}:${NodePort} mapping; k3d cannot add one to an existing cluster, so recreate it with: k3d cluster delete $ClusterName" 'WARN'
} else {
    Write-Log "$url is serving."
    if ($NoBrowser) {
        Write-Log "Browser launch suppressed (-NoBrowser)."
    } else {
        # Runs inside the worker's interactive session, so this opens in their
        # own desktop and their own default browser.
        Write-Log "Opening $url in the default browser..."
        Start-Process $url
    }
}

Write-Log "=== worker stack ready ==="
