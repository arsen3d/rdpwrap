<#
.SYNOPSIS
    Installs a locally-built RDP Wrapper (rdpwrap.dll) and verifies its dependencies.

.DESCRIPTION
    A from-source alternative to RDPWInst.exe. RDPWInst extracts its own embedded
    copy of rdpwrap.dll over the target path, so it cannot deploy a DLL you built
    yourself; this script deploys the artifacts in build\dist\ instead.

    Every install step is recorded to state.json in the install directory so that
    -Action Uninstall restores the original configuration exactly, rather than
    guessing at defaults.

.PARAMETER Action
    Check     - run dependency preflight only, change nothing (default).
    Install   - preflight, then install.
    Uninstall - restore the previous TermService configuration and remove files.

.PARAMETER SourcePath
    Directory holding rdpwrap.dll and rdpwrap.ini. Defaults to build\dist\<arch>.

.PARAMETER RfxvmtSource
    Path to a rfxvmt.dll to copy into System32 when the OS is missing it.
    Required on Windows 10+ builds that lack the file (see notes at the bottom).

.PARAMETER EnsureWSL
    Verify that the Windows Subsystem for Linux is present, and install it during
    -Action Install if it is not. WSL is NOT a dependency of RDP Wrapper; this
    exists only so one script can bring a machine to a known state. Off by
    default, because installing WSL enables Hyper-V platform features and
    usually requires a reboot.

.PARAMETER WSLDistro
    Distribution to install with WSL (for example 'Ubuntu-22.04'). When omitted,
    only the WSL platform is installed, with no distribution.

.PARAMETER EnsureDocker
    Verify Docker Desktop is installed and usable, and install it via winget
    during -Action Install if it is absent. Like -EnsureWSL, this is machine
    provisioning, not an RDP Wrapper dependency.

.PARAMETER DockerUser
    Account to add to the local 'docker-users' group. Membership is required to
    use Docker without elevation. Defaults to the invoking user.

.PARAMETER CreateWorkerUser
    Create a local account for RDP use, add it to 'Remote Desktop Users' and
    'docker-users', and register a logon task that starts Docker Desktop when
    that account signs in.

.PARAMETER WorkerUserName
    Name of the account to create. Defaults to 'worker'.

.PARAMETER WorkerPassword
    Password for the account. If omitted, the script prompts without echoing.
    Passing it on the command line leaves it in shell history.

.PARAMETER EnsureK3s
    Install k3d (k3s in Docker) machine-wide, and have the worker's logon script
    bring up a k3s cluster once the Docker engine is ready. Implies the worker
    account and Docker being present.

.PARAMETER K3sClusterName
    Name of the k3d cluster to create or start. Defaults to 'worker'.

.PARAMETER AddDefenderExclusion
    Add a Defender path exclusion for the install directory. Several AV products,
    Defender included, quarantine rdpwrap.dll. Off by default: this weakens
    scanning for that path, so it is your call, not the script's.

.PARAMETER Force
    Proceed even when the preflight finds a non-fatal problem, or when the
    current session is itself a Remote Desktop session (restarting TermService
    will disconnect you).

.EXAMPLE
    .\Install-RDPWrap.ps1 -Action Check
.EXAMPLE
    .\Install-RDPWrap.ps1 -Action Install -RfxvmtSource C:\temp\rfxvmt.dll
#>
[CmdletBinding()]
param(
    [ValidateSet('Check', 'Install', 'Uninstall')]
    [string] $Action = 'Check',
    [string] $SourcePath,
    [string] $RfxvmtSource,
    [switch] $EnsureWSL,
    [string] $WSLDistro,
    [switch] $EnsureDocker,
    [string] $DockerUser = $env:USERNAME,
    [switch] $CreateWorkerUser,
    [string] $WorkerUserName = 'worker',
    [string] $WorkerPassword,
    [switch] $EnsureK3s,
    [string] $K3sClusterName = 'worker',
    [switch] $AddDefenderExclusion,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'

$InstallDir   = Join-Path $env:ProgramFiles 'RDP Wrapper'
$WrapPathExp  = '%ProgramFiles%\RDP Wrapper\rdpwrap.dll'
$ParamsKey    = 'HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Parameters'
$TSKey        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$FirewallRule = 'RDP Wrapper'
$StateFile    = Join-Path $InstallDir 'state.json'

function Write-Step { param($m) Write-Host "[*] $m" }
function Write-Ok   { param($m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Bad  { param($m) Write-Host "[-] $m" -ForegroundColor Red }

# --------------------------------------------------------------------------
# PE import reader.
#
# The point of the whole exercise: rather than assuming which runtime DLLs the
# wrapper needs, read its import directory and confirm every named module
# actually resolves on this machine. A /MT build imports only kernel32 and
# user32; rebuild with /MD and this will correctly start demanding the VC++
# runtime instead.
# --------------------------------------------------------------------------
function Get-PEInfo {
    param([Parameter(Mandatory)][string] $Path)

    $b = [System.IO.File]::ReadAllBytes($Path)
    if ($b.Length -lt 64 -or $b[0] -ne 0x4D -or $b[1] -ne 0x5A) { throw "$Path is not a PE image." }

    $pe = [BitConverter]::ToInt32($b, 0x3C)
    if ([BitConverter]::ToUInt32($b, $pe) -ne 0x00004550) { throw "$Path has no PE signature." }

    $machine   = [BitConverter]::ToUInt16($b, $pe + 4)
    $nSections = [BitConverter]::ToUInt16($b, $pe + 6)
    $optSize   = [BitConverter]::ToUInt16($b, $pe + 20)
    $opt       = $pe + 24
    $magic     = [BitConverter]::ToUInt16($b, $opt)

    # Data directories sit after the optional header's fixed part; the offset
    # differs between PE32 (0x60) and PE32+ (0x70). Import table is index 1.
    $dataDir   = $opt + $(if ($magic -eq 0x20B) { 0x70 } else { 0x60 })
    $importRva = [BitConverter]::ToUInt32($b, $dataDir + 8)

    $sections = @()
    for ($i = 0; $i -lt $nSections; $i++) {
        $s = $opt + $optSize + ($i * 40)
        $sections += [pscustomobject]@{
            VirtualAddress = [BitConverter]::ToUInt32($b, $s + 12)
            VirtualSize    = [BitConverter]::ToUInt32($b, $s + 8)
            RawPointer     = [BitConverter]::ToUInt32($b, $s + 20)
        }
    }

    function ConvertTo-Offset {
        param($rva)
        foreach ($s in $sections) {
            if ($rva -ge $s.VirtualAddress -and $rva -lt ($s.VirtualAddress + $s.VirtualSize)) {
                return $s.RawPointer + ($rva - $s.VirtualAddress)
            }
        }
        return 0
    }

    $imports = @()
    if ($importRva -ne 0) {
        $d = ConvertTo-Offset $importRva
        # Import descriptors are 20 bytes each, terminated by an all-zero entry.
        while ($d -gt 0 -and [BitConverter]::ToUInt32($b, $d + 12) -ne 0) {
            $n = ConvertTo-Offset ([BitConverter]::ToUInt32($b, $d + 12))
            $sb = New-Object System.Text.StringBuilder
            while ($b[$n] -ne 0) { [void]$sb.Append([char]$b[$n]); $n++ }
            $imports += $sb.ToString()
            $d += 20
        }
    }

    [pscustomobject]@{
        Architecture = switch ($machine) { 0x014C { 'x86' } 0x8664 { 'x64' } 0xAA64 { 'arm64' } default { "unknown($machine)" } }
        Imports      = $imports
    }
}

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-RebootPending {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    foreach ($k in $keys) { if (Test-Path $k) { return $true } }
    $sm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue
    return [bool]($sm -and $sm.PendingFileRenameOperations)
}

# --------------------------------------------------------------------------
# WSL support.
#
# Unrelated to RDP Wrapper; present only so this script can bring a machine to
# a known state. wsl.exe writes UTF-16LE, so its output has to be decoded
# explicitly or every parse returns interleaved null bytes.
# --------------------------------------------------------------------------
# Windows PowerShell wraps a native command's stderr in ErrorRecords; with
# $ErrorActionPreference = 'Stop' that turns any tool writing to stderr into a
# terminating error, even when it exits 0. Probing tools legitimately write to
# stderr, so relax the preference for the duration of the call and judge the
# result by exit code instead.
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

function Invoke-Wsl {
    param([Parameter(ValueFromRemainingArguments)][string[]] $Arguments)

    $prev = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
        Invoke-NativeCapture { & wsl.exe @Arguments }
    } finally {
        [Console]::OutputEncoding = $prev
    }
}

function Get-WSLState {
    $exe = Get-Command wsl.exe -ErrorAction SilentlyContinue

    $version = $null
    $distros = @()
    if ($exe) {
        # 'wsl --version' exists only on the Store build; inbox WSL1 errors out.
        $v = Invoke-Wsl --version
        if ($v.ExitCode -eq 0 -and $v.Output) {
            $version = (($v.Output -join "`n") -split "`n" | Where-Object { $_ -match 'WSL version' } |
                        Select-Object -First 1) -replace '.*:\s*', ''
        }
        $d = Invoke-Wsl --list --quiet
        if ($d.ExitCode -eq 0 -and $d.Output) {
            $distros = @($d.Output | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ })
        }
    }

    # Feature state needs elevation; absence of an answer is not a failure.
    $features = @{}
    foreach ($f in 'Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform') {
        try { $features[$f] = (Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction Stop).State }
        catch { $features[$f] = 'unknown' }
    }

    # A running hypervisor masks VirtualizationFirmwareEnabled, reporting False
    # on machines where virtualization plainly works. Trust HypervisorPresent
    # first and only fall back to the firmware flag when no hypervisor is up.
    $hyperV = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
    $fw     = (Get-CimInstance Win32_Processor | Select-Object -First 1).VirtualizationFirmwareEnabled
    $virtOk = $hyperV -or $fw

    [pscustomobject]@{
        Present         = [bool]$exe
        Version         = $version
        Distros         = $distros
        Features        = $features
        VirtualizationOk = $virtOk
        HypervisorPresent = $hyperV
    }
}

function Install-WSLIfNeeded {
    $wsl = Get-WSLState

    if (-not $wsl.VirtualizationOk) {
        throw 'Hardware virtualization is not available. Enable Intel VT-x / AMD-V in firmware before installing WSL 2.'
    }

    if (-not $wsl.Present) {
        Write-Step "Installing WSL..."
        # --no-distribution keeps this to the platform only; installing a distro
        # otherwise launches interactive first-run setup, which would hang here.
        $wslArgs = if ($WSLDistro) { @('--install', '-d', $WSLDistro) } else { @('--install', '--no-distribution') }
        $r = Invoke-Wsl @wslArgs
        $r.Output | Write-Host
        if ($r.ExitCode -ne 0) { throw "wsl --install failed with exit code $($r.ExitCode)." }
        Write-Ok "WSL installed."
        Write-Warn "A reboot is required before WSL can be used."
        return
    }

    Write-Ok "WSL already present (version $($wsl.Version))."

    if ($WSLDistro -and $wsl.Distros -notcontains $WSLDistro) {
        Write-Step "Installing distribution '$WSLDistro'..."
        $r = Invoke-Wsl --install -d $WSLDistro
        $r.Output | Write-Host
        if ($r.ExitCode -ne 0) { throw "wsl --install -d $WSLDistro failed with exit code $($r.ExitCode)." }
        Write-Ok "Distribution '$WSLDistro' installed."
    } elseif ($WSLDistro) {
        Write-Ok "Distribution '$WSLDistro' already installed."
    }
}

# --------------------------------------------------------------------------
# Docker support.
#
# 'Installed' and 'usable' are different states worth reporting separately:
# Docker Desktop runs its engine from a per-user tray application, so the CLI
# can be on PATH and the daemon still unreachable.
# --------------------------------------------------------------------------
function Get-DockerState {
    $cli = Get-Command docker.exe -ErrorAction SilentlyContinue

    $cliVersion = $null
    if ($cli) {
        $v = Invoke-NativeCapture { & docker.exe --version }
        if ($v.ExitCode -eq 0) { $cliVersion = ($v.Output -join ' ').Trim() }
    }

    # Read the installed version from the uninstall registry rather than parsing
    # winget's column output, which is locale- and width-dependent.
    $desktop = Get-ItemProperty `
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq 'Docker Desktop' } | Select-Object -First 1

    $engineOk = $false
    if ($cli) {
        $engineOk = (Invoke-NativeCapture { & docker.exe info --format '{{.ServerVersion}}' }).ExitCode -eq 0
    }

    $inGroup = $false
    try {
        $inGroup = [bool](Get-LocalGroupMember -Group 'docker-users' -ErrorAction Stop |
            Where-Object { $_.Name -like "*\$DockerUser" -or $_.Name -eq $DockerUser })
    } catch { }

    [pscustomobject]@{
        CliPresent       = [bool]$cli
        CliVersion       = $cliVersion
        DesktopInstalled = [bool]$desktop
        DesktopVersion   = if ($desktop) { $desktop.DisplayVersion } else { $null }
        EngineRunning    = $engineOk
        UserInDockerGroup = $inGroup
    }
}

function Install-DockerIfNeeded {
    $docker = Get-DockerState

    if (-not $docker.DesktopInstalled) {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            throw 'winget is unavailable, so Docker Desktop cannot be installed automatically. Install App Installer from the Microsoft Store, or install Docker Desktop manually.'
        }
        Write-Step "Installing Docker Desktop via winget..."
        winget install --id Docker.DockerDesktop --exact --silent `
            --accept-package-agreements --accept-source-agreements | Write-Host
        if ($LASTEXITCODE -ne 0) { throw "winget install failed with exit code $LASTEXITCODE." }
        Write-Ok "Docker Desktop installed."
        Write-Warn "A reboot (or at least a sign-out) is required before Docker Desktop will run."
    } else {
        Write-Ok "Docker Desktop already installed (version $($docker.DesktopVersion))."
    }

    if (-not $docker.UserInDockerGroup) {
        Write-Step "Adding '$DockerUser' to the docker-users group..."
        try {
            Add-LocalGroupMember -Group 'docker-users' -Member $DockerUser -ErrorAction Stop
            Write-Ok "'$DockerUser' added; they must sign out and back in for it to apply."
        } catch {
            Write-Warn "Could not add '$DockerUser' to docker-users: $($_.Exception.Message)"
        }
    } else {
        Write-Ok "'$DockerUser' is already in docker-users."
    }

    # Deliberately not started here. The engine is launched by a per-user tray
    # application; starting it from an elevated provisioning context would run
    # it as the wrong user.
    if (-not $docker.EngineRunning) {
        Write-Warn "Docker engine is not running. Start Docker Desktop from your normal (non-elevated) session."
    }
}

# --------------------------------------------------------------------------
# Worker account.
#
# Creates a local RDP account and arranges for Docker Desktop to start when it
# logs on. Docker Desktop is a per-user tray application, so 'running' is a
# property of a logon session, not of the machine: it has to be launched inside
# the worker's own session, which is what the logon task below does.
# --------------------------------------------------------------------------
$WorkerTaskName = 'RDPWrap - Start Docker Desktop'

function Get-DockerDesktopExe {
    $candidates = @(
        (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Docker\Docker\Docker Desktop.exe')
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    return $null
}

function New-WorkerAccount {
    param([Parameter(Mandatory)][securestring] $Password)

    $existing = Get-LocalUser -Name $WorkerUserName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Ok "Account '$WorkerUserName' already exists; updating its password."
        Set-LocalUser -Name $WorkerUserName -Password $Password -PasswordNeverExpires $true
        if (-not $existing.Enabled) { Enable-LocalUser -Name $WorkerUserName }
    } else {
        Write-Step "Creating local account '$WorkerUserName'..."
        try {
            New-LocalUser -Name $WorkerUserName -Password $Password `
                -FullName 'RDP worker' -Description 'Automated RDP session account' `
                -PasswordNeverExpires -AccountNeverExpires -ErrorAction Stop | Out-Null
            Write-Ok "Account '$WorkerUserName' created."
        } catch {
            throw "Could not create '$WorkerUserName': $($_.Exception.Message). If this mentions the password, the local policy rejected it - choose a longer one or relax the policy."
        }
    }

    # Non-administrators need this group to sign in over RDP at all.
    foreach ($g in 'Remote Desktop Users', 'docker-users') {
        try {
            $members = @(Get-LocalGroupMember -Group $g -ErrorAction Stop | ForEach-Object { $_.Name })
            if ($members -notcontains "$env:COMPUTERNAME\$WorkerUserName") {
                Add-LocalGroupMember -Group $g -Member $WorkerUserName -ErrorAction Stop
                Write-Ok "Added '$WorkerUserName' to '$g'."
            } else {
                Write-Ok "'$WorkerUserName' already in '$g'."
            }
        } catch {
            Write-Warn "Could not add '$WorkerUserName' to '$g': $($_.Exception.Message)"
        }
    }
}

function Get-K3dPath {
    $cmd = Get-Command k3d -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in @(
        (Join-Path $env:ProgramFiles 'WinGet\Links\k3d.exe'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links\k3d.exe'))) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Install-K3dIfNeeded {
    if (Get-K3dPath) {
        Write-Ok "k3d already installed ($(Get-K3dPath))."
        return
    }
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw 'winget is unavailable, so k3d cannot be installed automatically. See https://k3d.io for manual installation.'
    }

    # Machine scope matters here: a user-scope install would land in the
    # administrator's WinGet\Links directory and never appear on worker's PATH.
    Write-Step "Installing k3d via winget (machine scope)..."
    $r = Invoke-NativeCapture {
        winget install --id k3d.k3d --exact --scope machine --silent `
            --accept-package-agreements --accept-source-agreements
    }
    $r.Output | Write-Host
    if ($r.ExitCode -ne 0) {
        Write-Warn "Machine-scope install failed (exit $($r.ExitCode)); retrying with the default scope."
        $r = Invoke-NativeCapture {
            winget install --id k3d.k3d --exact --silent `
                --accept-package-agreements --accept-source-agreements
        }
        $r.Output | Write-Host
        if ($r.ExitCode -ne 0) { throw "winget install k3d.k3d failed with exit code $($r.ExitCode)." }
        Write-Warn "k3d was installed in user scope; confirm it is on '$WorkerUserName' PATH."
    }
    Write-Ok "k3d installed."
}

function Register-DockerLogonTask {
    $exe = Get-DockerDesktopExe
    if (-not $exe) {
        Write-Warn "Docker Desktop executable not found; skipping the logon task. Install Docker first (-EnsureDocker)."
        return $false
    }

    # The logon task runs the worker stack script rather than Docker Desktop
    # directly: the k3d cluster can only be created after the engine is up, and
    # that only happens inside the worker's own session.
    $stackSrc = Join-Path $PSScriptRoot 'Start-WorkerStack.ps1'
    if (-not (Test-Path $stackSrc)) { throw "Start-WorkerStack.ps1 not found next to this script." }

    # Copied into the install directory so the worker can read it regardless of
    # where the repository lives or what its permissions are.
    $stackDst = Join-Path $InstallDir 'Start-WorkerStack.ps1'
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item $stackSrc $stackDst -Force
    Write-Ok "Logon script installed to $stackDst"

    $cluster = if ($EnsureK3s) { $K3sClusterName } else { '' }

    Write-Step "Registering logon task for '$WorkerUserName'..."
    $account   = "$env:COMPUTERNAME\$WorkerUserName"
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
                    -Argument ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass ' +
                               "-File `"$stackDst`" -ClusterName `"$cluster`"")
    $trigger   = New-ScheduledTaskTrigger -AtLogOn -User $account
    # Interactive/Limited: the tray app must run inside the worker's own desktop
    # session and does not need elevation.
    $principal = New-ScheduledTaskPrincipal -UserId $account -LogonType Interactive -RunLevel Limited
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
                    -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)

    Register-ScheduledTask -TaskName $WorkerTaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force | Out-Null
    Write-Ok "Logon task '$WorkerTaskName' registered."
    return $true
}

# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------
function Invoke-Preflight {
    $problems = @()
    $osArch   = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }

    Write-Step "Checking privileges..."
    if (Test-Administrator) { Write-Ok "Running elevated." }
    else { $problems += 'Not running as Administrator. Re-launch PowerShell elevated.'; Write-Bad "Not elevated." }

    Write-Step "Checking Windows version..."
    $osVer  = [Environment]::OSVersion.Version
    $cv     = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    Write-Ok "$($cv.ProductName) $($cv.DisplayVersion) ($osVer), edition $($cv.EditionID), $osArch."
    if ($osVer.Major -lt 6) { $problems += 'Windows 2000/XP/2003 are not supported by RDP Wrapper.' }

    Write-Step "Locating build artifacts..."
    if (-not $SourcePath) {
        $SourcePath = Join-Path (Split-Path $PSScriptRoot -Parent) "build\dist\$osArch"
    }
    $dllSrc = Join-Path $SourcePath 'rdpwrap.dll'
    $iniSrc = Join-Path $SourcePath 'rdpwrap.ini'
    if (Test-Path $dllSrc) { Write-Ok "DLL: $dllSrc" } else { $problems += "rdpwrap.dll not found at $dllSrc. Build it first."; Write-Bad "Missing $dllSrc" }
    if (Test-Path $iniSrc) { Write-Ok "INI: $iniSrc" } else { $problems += "rdpwrap.ini not found at $iniSrc."; Write-Bad "Missing $iniSrc" }

    if (Test-Path $dllSrc) {
        Write-Step "Verifying DLL architecture and imports..."
        $pe = Get-PEInfo -Path $dllSrc
        if ($pe.Architecture -eq $osArch) {
            Write-Ok "Architecture $($pe.Architecture) matches the OS."
        } else {
            $problems += "rdpwrap.dll is $($pe.Architecture) but this OS is $osArch."
            Write-Bad "Architecture mismatch: DLL is $($pe.Architecture), OS is $osArch."
        }

        # TermService loads this DLL, so anything it imports must already resolve
        # from System32 -- there is no application directory to fall back on.
        $sys = Join-Path $env:SystemRoot 'System32'
        foreach ($imp in $pe.Imports) {
            if (Test-Path (Join-Path $sys $imp)) {
                Write-Ok "Import satisfied: $imp"
            } else {
                $problems += "Imported module '$imp' is not present in System32. If this is a VC++ runtime DLL, either install the matching redistributable or rebuild with /MT (static CRT)."
                Write-Bad "Import NOT satisfied: $imp"
            }
        }
    }

    Write-Step "Checking termsrv.dll support in the INI..."
    $termsrv = Join-Path $env:SystemRoot 'System32\termsrv.dll'
    $tsVer   = (Get-Item $termsrv).VersionInfo.FileVersion -replace ' .*', ''
    Write-Ok "termsrv.dll version $tsVer"
    if (Test-Path $iniSrc) {
        if (Select-String -Path $iniSrc -Pattern "^\[$([regex]::Escape($tsVer))\]" -Quiet) {
            Write-Ok "INI contains a [$tsVer] section."
        } else {
            $problems += "rdpwrap.ini has no [$tsVer] section. RDP Wrapper will report [not supported]. Run bin\autoupdate.bat, or fetch a community INI, before installing."
            Write-Bad "No [$tsVer] section in the INI."
        }
    }

    Write-Step "Checking rfxvmt.dll..."
    $rfxTarget = Join-Path $env:SystemRoot 'System32\rfxvmt.dll'
    if (Test-Path $rfxTarget) {
        Write-Ok "rfxvmt.dll present."
    } elseif ($RfxvmtSource -and (Test-Path $RfxvmtSource)) {
        Write-Ok "rfxvmt.dll missing; will install from $RfxvmtSource."
    } else {
        $problems += "rfxvmt.dll is missing from System32 and no -RfxvmtSource was supplied. Without it the listener reports [not listening]. See the notes at the end of this script."
        Write-Bad "rfxvmt.dll missing and no source supplied."
    }

    Write-Step "Checking TermService..."
    $svc = Get-Service TermService -ErrorAction SilentlyContinue
    if ($svc) {
        $dll = (Get-ItemProperty $ParamsKey -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll
        Write-Ok "TermService present (status $($svc.Status)), ServiceDll = $dll"
        if ($dll -and $dll -match 'rdpwrap\.dll') { Write-Warn "RDP Wrapper appears to be installed already; it will be replaced." }
    } else {
        $problems += 'TermService is not installed on this system.'
        Write-Bad "TermService not found."
    }

    if ($EnsureWSL) {
        Write-Step "Checking WSL..."
        $wsl = Get-WSLState
        if ($wsl.Present) {
            Write-Ok "WSL present$(if ($wsl.Version) { " (version $($wsl.Version))" })."
            if ($wsl.Distros) { Write-Ok "Distributions: $($wsl.Distros -join ', ')" }
            else { Write-Warn "No distributions installed." }
            if ($WSLDistro -and $wsl.Distros -notcontains $WSLDistro) {
                Write-Warn "Requested distribution '$WSLDistro' is not installed; Install will add it."
            }
        } else {
            Write-Warn "WSL is not installed; Install will add it."
        }

        if ($wsl.VirtualizationOk) {
            Write-Ok "Hardware virtualization available (HypervisorPresent = $($wsl.HypervisorPresent))."
        } else {
            $problems += 'Hardware virtualization is unavailable. Enable Intel VT-x / AMD-V in firmware before WSL 2 can run.'
            Write-Bad "Hardware virtualization unavailable."
        }

        if (Test-RebootPending) { Write-Warn "A reboot is already pending; WSL changes may not take effect until it is done." }
    }

    if ($EnsureDocker) {
        Write-Step "Checking Docker..."
        $docker = Get-DockerState
        if ($docker.DesktopInstalled) { Write-Ok "Docker Desktop installed (version $($docker.DesktopVersion))." }
        else { Write-Warn "Docker Desktop is not installed; Install will add it via winget." }

        if ($docker.CliPresent) { Write-Ok "CLI: $($docker.CliVersion)" }

        if ($docker.EngineRunning) {
            Write-Ok "Docker engine is reachable."
        } else {
            Write-Warn "Docker engine is NOT reachable. Installed but not running counts as not usable; start Docker Desktop from your normal session."
        }

        if ($docker.UserInDockerGroup) {
            Write-Ok "'$DockerUser' is in the docker-users group."
        } else {
            Write-Warn "'$DockerUser' is not in docker-users; Install will add them."
        }

        # Docker Desktop defaults to the WSL 2 backend, so a machine without WSL
        # gets a Docker that installs cleanly and then cannot start.
        if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
            Write-Warn "WSL is absent. Docker Desktop's default WSL 2 backend needs it - pass -EnsureWSL as well."
        }
    }

    if ($CreateWorkerUser) {
        Write-Step "Checking worker account '$WorkerUserName'..."
        $existing = Get-LocalUser -Name $WorkerUserName -ErrorAction SilentlyContinue
        if ($existing) { Write-Warn "Account '$WorkerUserName' already exists; Install will reset its password and group membership." }
        else { Write-Ok "Account '$WorkerUserName' does not exist yet; Install will create it." }

        if ($WorkerPassword) {
            if ($WorkerPassword.Length -lt 8 -or $WorkerPassword -eq $WorkerUserName) {
                Write-Warn "The chosen password is weak and this account is reachable over RDP. Restrict port 3389 to trusted networks."
            }
        }

        $minLen = (net accounts | Select-String 'Minimum password length' | ForEach-Object { ($_ -split ':')[1].Trim() })
        Write-Ok "Local minimum password length: $minLen"

        if (Get-DockerDesktopExe) { Write-Ok "Docker Desktop executable found for the logon task." }
        else { Write-Warn "Docker Desktop is not installed, so the logon task cannot be created. Add -EnsureDocker." }

        # RDP Wrapper is what allows this session to coexist with the console
        # user's; without it the worker's logon evicts whoever is on the console.
        Write-Ok "Concurrent sessions rely on the wrapper being installed and supported."
    }

    if ($EnsureK3s) {
        Write-Step "Checking k3s / k3d..."
        $k3d = Get-K3dPath
        if ($k3d) { Write-Ok "k3d present: $k3d" }
        else { Write-Warn "k3d is not installed; Install will add it via winget (k3d.k3d)." }

        if (-not (Test-Path (Join-Path $PSScriptRoot 'Start-WorkerStack.ps1'))) {
            $problems += 'Start-WorkerStack.ps1 is missing from the installer directory; the logon task cannot be registered without it.'
            Write-Bad "Start-WorkerStack.ps1 not found."
        } else {
            Write-Ok "Worker logon script found."
        }

        if (-not $CreateWorkerUser) {
            Write-Warn "-EnsureK3s without -CreateWorkerUser installs k3d but registers no logon task."
        }

        # The cluster is created on first logon, not here: k3d needs a running
        # engine, and Docker Desktop's engine belongs to a user session.
        Write-Ok "Cluster '$K3sClusterName' will be created on the worker's first logon."

        # Docker Desktop registers its WSL distro per Windows user (HKCU\...\Lxss)
        # and stores the engine's disk under that user's LOCALAPPDATA, so the
        # worker's containers -- and therefore the k3s cluster -- are private to
        # the worker account rather than shared with the console user.
        $ownDistro = Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' -ErrorAction SilentlyContinue |
            ForEach-Object { Get-ItemProperty $_.PSPath } |
            Where-Object { $_.DistributionName -eq 'docker-desktop' } | Select-Object -First 1
        if ($ownDistro) {
            Write-Ok "This account's Docker distro: $($ownDistro.BasePath -replace '^\\\\\?\\', '')"
        }
        Write-Ok "'$WorkerUserName' will get its own Docker distro and data disk on first launch (several GB, first logon is slow)."
    }

    if ($env:SESSIONNAME -and $env:SESSIONNAME -notlike 'Console*') {
        Write-Warn "You are running inside session '$env:SESSIONNAME'. Restarting TermService will disconnect you. Use -Force to proceed anyway."
        if (-not $Force) { $problems += 'Refusing to restart TermService from a remote session without -Force.' }
    }

    [pscustomobject]@{ Problems = $problems; SourcePath = $SourcePath; TermsrvVersion = $tsVer }
}

# --------------------------------------------------------------------------
# Install / Uninstall
# --------------------------------------------------------------------------
function Invoke-Install {
    param($Pre)

    # Done first: it is independent of the wrapper, and may want a reboot that
    # is better surfaced before TermService is touched.
    # WSL before Docker: Docker Desktop's default backend depends on it.
    if ($EnsureWSL)    { Install-WSLIfNeeded }
    if ($EnsureDocker) { Install-DockerIfNeeded }
    if ($EnsureK3s)    { Install-K3dIfNeeded }

    $workerTaskRegistered = $false
    if ($CreateWorkerUser) {
        $secure = if ($WorkerPassword) {
            ConvertTo-SecureString $WorkerPassword -AsPlainText -Force
        } else {
            Read-Host -Prompt "Password for '$WorkerUserName'" -AsSecureString
        }
        New-WorkerAccount -Password $secure
        $workerTaskRegistered = Register-DockerLogonTask
    }

    $svc = Get-Service TermService
    $originalDll  = (Get-ItemProperty $ParamsKey -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll
    # Anchor on the leading whitespace so this does not also match START_TYPE.
    $originalType = (sc.exe qc TermService |
        Select-String '^\s+TYPE\s+:\s+\S+\s+(\S+)' |
        Select-Object -First 1).Matches.Groups[1].Value

    Write-Step "Stopping TermService..."
    if ($svc.Status -ne 'Stopped') { Stop-Service TermService -Force }

    Write-Step "Installing files to $InstallDir..."
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item (Join-Path $Pre.SourcePath 'rdpwrap.dll') $InstallDir -Force
    Copy-Item (Join-Path $Pre.SourcePath 'rdpwrap.ini') $InstallDir -Force
    Write-Ok "rdpwrap.dll and rdpwrap.ini copied."

    $rfxTarget = Join-Path $env:SystemRoot 'System32\rfxvmt.dll'
    $rfxInstalled = $false
    if (-not (Test-Path $rfxTarget) -and $RfxvmtSource) {
        Write-Step "Installing rfxvmt.dll to System32..."
        Copy-Item $RfxvmtSource $rfxTarget -Force
        $rfxInstalled = $true
        Write-Ok "rfxvmt.dll installed."
    }

    # Save enough state to undo precisely what we changed.
    @{
        OriginalServiceDll  = $originalDll
        OriginalServiceType = $originalType
        InstalledRfxvmt     = $rfxInstalled
        EnsuredWSL          = [bool]$EnsureWSL
        EnsuredDocker       = [bool]$EnsureDocker
        WorkerUserName      = if ($CreateWorkerUser) { $WorkerUserName } else { $null }
        WorkerTaskName      = if ($workerTaskRegistered) { $WorkerTaskName } else { $null }
        K3sClusterName      = if ($EnsureK3s) { $K3sClusterName } else { $null }
        DefenderExclusion   = [bool]$AddDefenderExclusion
        InstalledAt         = (Get-Date).ToString('o')
    } | ConvertTo-Json | Set-Content -Path $StateFile -Encoding utf8

    Write-Step "Pointing TermService at the wrapper..."
    New-ItemProperty -Path $ParamsKey -Name ServiceDll -PropertyType ExpandString -Value $WrapPathExp -Force | Out-Null
    Write-Ok "ServiceDll = $WrapPathExp"

    # Isolating TermService into its own svchost keeps an unstable wrapper from
    # taking neighbouring services down with it.
    Write-Step "Isolating TermService into its own svchost process..."
    sc.exe config TermService type= own | Out-Null
    Write-Ok "TermService type set to 'own' (was '$originalType')."

    Write-Step "Enabling Remote Desktop connections..."
    New-ItemProperty -Path $TSKey -Name fDenyTSConnections -PropertyType DWord -Value 0 -Force | Out-Null
    Write-Ok "fDenyTSConnections = 0"

    Write-Step "Adding firewall rules..."
    # Named distinctly so uninstall never removes Windows' built-in RDP rules.
    netsh advfirewall firewall delete rule name="$FirewallRule" | Out-Null
    netsh advfirewall firewall add rule name="$FirewallRule" dir=in protocol=tcp localport=3389 profile=any action=allow | Out-Null
    netsh advfirewall firewall add rule name="$FirewallRule" dir=in protocol=udp localport=3389 profile=any action=allow | Out-Null
    Write-Ok "Firewall rules '$FirewallRule' added for TCP/UDP 3389."

    if ($AddDefenderExclusion) {
        Write-Step "Adding Defender exclusion for $InstallDir..."
        Add-MpPreference -ExclusionPath $InstallDir
        Write-Warn "Defender will no longer scan $InstallDir."
    }

    Write-Step "Starting TermService..."
    Set-Service TermService -StartupType Automatic
    Start-Service TermService

    Start-Sleep -Seconds 2
    $listening = Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue
    if ($listening) { Write-Ok "Port 3389 is listening. Installation complete." }
    else { Write-Warn "Port 3389 is not listening yet. Check the Terminal Services event log; a reboot is sometimes needed." }
}

function Invoke-Uninstall {
    if (-not (Test-Administrator)) { throw 'Uninstall requires an elevated PowerShell session.' }

    $state = if (Test-Path $StateFile) { Get-Content $StateFile -Raw | ConvertFrom-Json } else { $null }
    if (-not $state) { Write-Warn "No state.json found; falling back to stock defaults." }

    Write-Step "Stopping TermService..."
    $svc = Get-Service TermService -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') { Stop-Service TermService -Force }

    $restoreDll  = if ($state -and $state.OriginalServiceDll)  { $state.OriginalServiceDll }  else { '%SystemRoot%\System32\termsrv.dll' }
    $restoreType = if ($state -and $state.OriginalServiceType) { $state.OriginalServiceType } else { 'share' }

    Write-Step "Restoring ServiceDll..."
    New-ItemProperty -Path $ParamsKey -Name ServiceDll -PropertyType ExpandString -Value $restoreDll -Force | Out-Null
    Write-Ok "ServiceDll = $restoreDll"

    Write-Step "Restoring service type..."
    $typeArg = if ($restoreType -match 'SHARE') { 'share' } else { 'own' }
    sc.exe config TermService type= $typeArg | Out-Null
    Write-Ok "TermService type = $typeArg"

    Write-Step "Removing firewall rules..."
    netsh advfirewall firewall delete rule name="$FirewallRule" | Out-Null

    if ($state -and $state.DefenderExclusion) {
        Write-Step "Removing Defender exclusion..."
        Remove-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
    }

    if ($state -and $state.WorkerTaskName) {
        Write-Step "Removing logon task '$($state.WorkerTaskName)'..."
        Unregister-ScheduledTask -TaskName $state.WorkerTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Ok "Logon task removed."
    }

    if ($state -and $state.K3sClusterName) {
        # Cluster containers and volumes live in the worker's Docker engine,
        # which is not running in this context, so this cannot be done here.
        Write-Warn "k3d cluster '$($state.K3sClusterName)' is left in place. Remove it from the worker's session:"
        Write-Host "        k3d cluster delete $($state.K3sClusterName)"
    }

    if ($state -and $state.WorkerUserName) {
        # Deleting an account is not reversible and may orphan a user profile,
        # so it is reported rather than performed.
        Write-Warn "Local account '$($state.WorkerUserName)' is left in place. Remove it yourself if you want it gone:"
        Write-Host "        Remove-LocalUser -Name '$($state.WorkerUserName)'"
    }

    if ($state -and $state.EnsuredDocker) {
        Write-Warn "Docker Desktop is left installed, as is docker-users group membership."
    }

    if ($state -and $state.EnsuredWSL) {
        Write-Warn "WSL is left installed. It is shared machine-wide infrastructure and unrelated to RDP Wrapper; remove it yourself if you want it gone."
    }

    if ($state -and $state.InstalledRfxvmt) {
        Write-Warn "rfxvmt.dll was installed by this script into System32. It is left in place: other components may now rely on it. Delete it manually if you want it gone."
    }

    Write-Step "Removing $InstallDir..."
    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }

    Start-Service TermService
    Write-Ok "Uninstall complete; stock Terminal Services restored."
}

# --------------------------------------------------------------------------
Write-Host ""
Write-Host "RDP Wrapper installer (from-source build)" -ForegroundColor Cyan
Write-Host "-----------------------------------------"

$pre = Invoke-Preflight
Write-Host ""

if ($pre.Problems.Count -gt 0) {
    Write-Bad "Preflight found $($pre.Problems.Count) problem(s):"
    $pre.Problems | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
    Write-Host ""
    if ($Action -eq 'Install' -and -not $Force) {
        throw "Refusing to install. Resolve the problems above, or re-run with -Force to override."
    }
} else {
    Write-Ok "All dependency checks passed."
    Write-Host ""
}

switch ($Action) {
    'Check'     { Write-Host "Check-only run; nothing was modified." }
    'Install'   { Invoke-Install -Pre $pre }
    'Uninstall' { Invoke-Uninstall }
}

<#
NOTE ON rfxvmt.dll
    rfxvmt.dll ships with Microsoft's RemoteFX components and is absent from
    some Windows editions and builds. RDP Wrapper needs it or the listener
    reports [not listening]. It is a Microsoft binary, so this script will not
    download one; supply a path with -RfxvmtSource. Reasonable sources are
    another machine of the same Windows build and architecture, or the copy
    embedded in an official RDPWInst.exe release. Verify the version and digital
    signature before installing a system DLL from anywhere.
#>
