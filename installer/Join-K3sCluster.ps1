<#
.SYNOPSIS
    Joins this Windows machine to a remote k3s cluster as an agent node, by
    running the k3s agent inside a WSL 2 distribution.

.DESCRIPTION
    k3s agents are Linux-only; there is no native Windows k3s node. The agent
    therefore runs inside WSL 2, which needs two things to work properly:

      systemd as pid 1   - k3s installs itself as a systemd unit
      mirrored networking - under the default NAT mode the WSL VM sits behind a
                            private address, so the control plane cannot reach
                            the agent's kubelet on 10250 and 'kubectl logs' and
                            'kubectl exec' fail for pods scheduled here

    Both are verified before anything is installed.

.PARAMETER ServerUrl
    URL of the k3s API server, for example https://10.0.0.28:6443. Use an IP
    rather than an mDNS name: .local names do not resolve inside WSL.

.PARAMETER NodeTokenFile
    Path to a file containing the server's node token, taken from
    /var/lib/rancher/k3s/server/node-token on the k3s server. Preferred over
    -NodeToken, which would leave the secret in shell history.

.PARAMETER NodeToken
    The node token as a string. Convenient but ends up in your shell history.

.PARAMETER Distro
    WSL distribution to host the agent. Defaults to Ubuntu-22.04.

.PARAMETER NodeName
    Name this node registers under. Defaults to <hostname>-wsl.

.PARAMETER Uninstall
    Remove the k3s agent from the distribution and deregister the node.

.EXAMPLE
    .\Join-K3sCluster.ps1 -ServerUrl https://10.0.0.28:6443 -NodeTokenFile C:\temp\node-token
.EXAMPLE
    .\Join-K3sCluster.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string] $ServerUrl,
    [string] $NodeTokenFile,
    [string] $NodeToken,
    [string] $Distro   = 'Ubuntu-22.04',
    [string] $NodeName = "$env:COMPUTERNAME-wsl".ToLower(),
    [switch] $Uninstall,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'

function Write-Step { param($m) Write-Host "[*] $m" }
function Write-Ok   { param($m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Bad  { param($m) Write-Host "[-] $m" -ForegroundColor Red }

# wsl.exe emits UTF-16LE, and Windows PowerShell turns a native command's stderr
# into terminating errors under $ErrorActionPreference = 'Stop'. Handle both.
function Invoke-Wsl {
    param([Parameter(ValueFromRemainingArguments)][string[]] $Arguments)

    $prevEnc = [Console]::OutputEncoding
    $prevEA  = $ErrorActionPreference
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
        $ErrorActionPreference = 'Continue'
        $out = & wsl.exe @Arguments 2>&1
        [pscustomobject]@{ Output = $out; ExitCode = $LASTEXITCODE }
    } finally {
        [Console]::OutputEncoding = $prevEnc
        $ErrorActionPreference = $prevEA
    }
}

# Runs a shell snippet in the distro. Anything secret is passed through the
# environment rather than the command line, so it never reaches the process
# table or a log.
function Invoke-InDistro {
    param([Parameter(Mandatory)][string] $Script, [switch] $AsRoot)

    $args = @('-d', $Distro)
    if ($AsRoot) { $args += @('-u', 'root') }
    $args += @('--', 'bash', '-lc', $Script)
    Invoke-Wsl @args
}

function Test-Prerequisites {
    $problems = @()

    Write-Step "Checking WSL distribution '$Distro'..."
    $list = Invoke-Wsl --list --quiet
    $distros = @($list.Output | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ })
    if ($distros -contains $Distro) { Write-Ok "Distribution '$Distro' present." }
    else {
        $problems += "WSL distribution '$Distro' not found. Available: $($distros -join ', ')"
        Write-Bad "Distribution '$Distro' not found."
        return $problems
    }

    Write-Step "Checking systemd..."
    $pid1 = Invoke-InDistro 'ps -p 1 -o comm='
    if (($pid1.Output -join '').Trim() -eq 'systemd') {
        Write-Ok "systemd is pid 1."
    } else {
        $problems += "systemd is not pid 1 in '$Distro'. Add '[boot]`nsystemd=true' to /etc/wsl.conf, then run 'wsl --shutdown'."
        Write-Bad "systemd is not pid 1 (found '$(($pid1.Output -join '').Trim())')."
    }

    Write-Step "Checking WSL networking mode..."
    $cfg = Join-Path $env:USERPROFILE '.wslconfig'
    $mirrored = (Test-Path $cfg) -and ((Get-Content $cfg -Raw) -match 'networkingMode\s*=\s*mirrored')
    if ($mirrored) {
        Write-Ok "Mirrored networking enabled; the control plane can reach this node's kubelet."
    } else {
        # Not fatal: the node will join and run pods. Only the control-plane to
        # kubelet direction breaks, which is exactly what logs and exec need.
        Write-Warn "Mirrored networking is NOT enabled. The node will join, but 'kubectl logs' and 'kubectl exec' against pods here will fail."
        Write-Warn "Add 'networkingMode=mirrored' under [wsl2] in $cfg and run 'wsl --shutdown'."
    }

    if ($ServerUrl) {
        Write-Step "Checking the API server is reachable from inside WSL..."
        $u = [uri]$ServerUrl
        if ($u.Host -match '\.local$') {
            $problems += "'$($u.Host)' is an mDNS name and will not resolve inside WSL. Use the IP address."
            Write-Bad "mDNS name '$($u.Host)' cannot be resolved from WSL."
        } else {
            $port = if ($u.Port -gt 0) { $u.Port } else { 6443 }
            $probe = Invoke-InDistro "timeout 5 bash -c '</dev/tcp/$($u.Host)/$port' 2>/dev/null && echo OPEN || echo CLOSED"
            if (($probe.Output -join '') -match 'OPEN') {
                Write-Ok "$($u.Host):$port reachable from WSL."
            } else {
                $problems += "$($u.Host):$port is not reachable from inside WSL. The k3s server must be listening and exposed on the LAN, not just on its own loopback."
                Write-Bad "$($u.Host):$port not reachable."
            }
        }
    }

    return $problems
}

function Install-Agent {
    $token = if ($NodeTokenFile) {
        if (-not (Test-Path $NodeTokenFile)) { throw "Node token file not found: $NodeTokenFile" }
        (Get-Content $NodeTokenFile -Raw).Trim()
    } elseif ($NodeToken) {
        $NodeToken.Trim()
    } else {
        throw 'Supply -NodeTokenFile (preferred) or -NodeToken. Take it from /var/lib/rancher/k3s/server/node-token on the k3s server.'
    }
    if (-not $token) { throw 'The node token is empty.' }

    Write-Step "Installing the k3s agent in '$Distro' as node '$NodeName'..."
    # The token goes in via the environment, so it never appears in the command
    # line, the process table, or this script's output.
    $script = @'
set -eu
if ! command -v curl >/dev/null 2>&1; then
  apt-get update -qq && apt-get install -y -qq curl
fi
curl -sfL https://get.k3s.io | \
  K3S_URL="$JOIN_SERVER_URL" \
  K3S_TOKEN="$JOIN_TOKEN" \
  INSTALL_K3S_EXEC="agent --node-name $JOIN_NODE_NAME" \
  sh -
'@
    $env:WSLENV = 'JOIN_SERVER_URL/u:JOIN_TOKEN/u:JOIN_NODE_NAME/u'
    $env:JOIN_SERVER_URL = $ServerUrl
    $env:JOIN_TOKEN      = $token
    $env:JOIN_NODE_NAME  = $NodeName
    try {
        $r = Invoke-InDistro -Script $script -AsRoot
        $r.Output | Write-Host
        if ($r.ExitCode -ne 0) { throw "k3s agent install failed with exit code $($r.ExitCode)." }
    } finally {
        Remove-Item Env:JOIN_TOKEN, Env:JOIN_SERVER_URL, Env:JOIN_NODE_NAME, Env:WSLENV -ErrorAction SilentlyContinue
    }

    Write-Step "Verifying the agent service..."
    $status = Invoke-InDistro 'systemctl is-active k3s-agent || true' -AsRoot
    $state = ($status.Output -join '').Trim()
    if ($state -eq 'active') {
        Write-Ok "k3s-agent is active."
    } else {
        Write-Warn "k3s-agent reports '$state'. Recent log:"
        (Invoke-InDistro 'journalctl -u k3s-agent -n 30 --no-pager || true' -AsRoot).Output | Write-Host
        throw 'The k3s agent did not come up. See the log above.'
    }

    Write-Host ""
    Write-Ok "Node '$NodeName' joined $ServerUrl."
    Write-Host "Confirm from the server with:  kubectl get nodes" -ForegroundColor Cyan
    Write-Host ""
    Write-Warn "WSL does not start automatically at boot. To bring the node back after a restart, run any WSL command (or 'wsl -d $Distro true') to start the distro."
}

function Uninstall-Agent {
    Write-Step "Removing the k3s agent from '$Distro'..."
    $r = Invoke-InDistro '[ -x /usr/local/bin/k3s-agent-uninstall.sh ] && /usr/local/bin/k3s-agent-uninstall.sh || echo "no k3s agent installed"' -AsRoot
    $r.Output | Write-Host
    Write-Ok "Agent removed. Delete the node from the server with: kubectl delete node $NodeName"
}

# --------------------------------------------------------------------------
Write-Host ""
Write-Host "Join this machine to a k3s cluster (agent in WSL 2)" -ForegroundColor Cyan
Write-Host "---------------------------------------------------"

if ($Uninstall) { Uninstall-Agent; return }

if (-not $ServerUrl) { throw 'Specify -ServerUrl, for example https://10.0.0.28:6443' }

$problems = Test-Prerequisites
Write-Host ""

if ($problems.Count -gt 0) {
    Write-Bad "Preflight found $($problems.Count) problem(s):"
    $problems | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
    Write-Host ""
    if (-not $Force) { throw 'Refusing to join. Resolve the problems above, or re-run with -Force.' }
}

Install-Agent
