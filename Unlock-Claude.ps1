<#
.SYNOPSIS
    Finds processes locking Claude Desktop's (or Cowork's) files/folders and offers to stop them.

.DESCRIPTION
    Claude Desktop occasionally fails to launch with an error like:
        "Another program is currently using this file."
    referencing a path under C:\Program Files\WindowsApps\Claude_<version>...
    This usually means a leftover Claude/Electron process (main app, a renderer,
    or a helper) didn't fully exit after a crash and is still holding a handle
    open on one of its own files. Cowork ships as its own packaged executable
    under the same WindowsApps mechanism, so it's checked for the same kind of
    leftover lock even if you haven't run a Cowork task recently.

    This script:
      1. Uses the native Windows Restart Manager API (the built-in equivalent
         of `lsof` on Windows - no third-party tools required) to ask Windows
         exactly which running processes have a lock on the relevant Claude
         and Cowork paths.
      2. Also does a broader sweep for any process whose name or executable
         path looks like it belongs to Claude or Cowork, in case it isn't
         holding a lock on a file this script checked but is still stuck.
      3. Shows you what it found and asks for confirmation (per process)
         before stopping anything. Nothing is killed silently.

.NOTES
    Run this from a normal PowerShell window. Elevation (Run as Administrator)
    is recommended so it can see/stop processes owned by other sessions and
    so the Restart Manager check can see all handles.
#>

[CmdletBinding()]
param(
    # Extra file or folder paths you want checked for locks, in addition to
    # the default Claude locations this script already knows about.
    [string[]]$ExtraPaths = @()
)

$ErrorActionPreference = 'Stop'

function Write-Section($text) {
    Write-Host ""
    Write-Host "== $text ==" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# 1. Figure out which Claude-related paths to check for locks
# ---------------------------------------------------------------------------

Write-Section "Locating Claude installation paths"

$candidatePaths = New-Object System.Collections.Generic.List[string]

# MSIX/WindowsApps package installs - Claude Desktop and Cowork (Cowork tasks
# spin up their own packaged executable, so it can be left locked the same way)
$windowsApps = Join-Path $env:ProgramFiles 'WindowsApps'
if (Test-Path $windowsApps) {
    Get-ChildItem -Path $windowsApps -Directory -Filter 'Claude_*' -ErrorAction SilentlyContinue |
        ForEach-Object { $candidatePaths.Add($_.FullName) }
    Get-ChildItem -Path $windowsApps -Directory -Filter '*Cowork*' -ErrorAction SilentlyContinue |
        ForEach-Object { $candidatePaths.Add($_.FullName) }
}

# Per-user packaged app data
$packages = Join-Path $env:LOCALAPPDATA 'Packages'
if (Test-Path $packages) {
    Get-ChildItem -Path $packages -Directory -Filter '*Claude*' -ErrorAction SilentlyContinue |
        ForEach-Object { $candidatePaths.Add($_.FullName) }
    Get-ChildItem -Path $packages -Directory -Filter '*Cowork*' -ErrorAction SilentlyContinue |
        ForEach-Object { $candidatePaths.Add($_.FullName) }
}

# Roaming app data (settings, scratch workspaces, logs, etc.)
$roaming = Join-Path $env:APPDATA 'Claude'
if (Test-Path $roaming) { $candidatePaths.Add($roaming) }

# Local app data (some Electron apps also cache here)
$local = Join-Path $env:LOCALAPPDATA 'Claude'
if (Test-Path $local) { $candidatePaths.Add($local) }
$localCowork = Join-Path $env:LOCALAPPDATA 'Cowork'
if (Test-Path $localCowork) { $candidatePaths.Add($localCowork) }

foreach ($p in $ExtraPaths) { $candidatePaths.Add($p) }

if ($candidatePaths.Count -eq 0) {
    Write-Warning "No Claude install paths were found automatically. Pass -ExtraPaths to point at specific folders/files."
} else {
    $candidatePaths | Select-Object -Unique | ForEach-Object { Write-Host "  $_" }
}

# Restart Manager needs individual FILES, not folders, so expand folders out.
# Limit how many files we enumerate per folder to keep this fast.
$filesToCheck = New-Object System.Collections.Generic.List[string]
foreach ($p in ($candidatePaths | Select-Object -Unique)) {
    if (-not (Test-Path $p)) { continue }
    $item = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
    if ($null -eq $item) { continue }
    if ($item.PSIsContainer) {
        Get-ChildItem -LiteralPath $p -Recurse -File -ErrorAction SilentlyContinue |
            Select-Object -First 500 |
            ForEach-Object { $filesToCheck.Add($_.FullName) }
    } else {
        $filesToCheck.Add($item.FullName)
    }
}

# ---------------------------------------------------------------------------
# 2. Native Windows Restart Manager API - the real "lsof" for Windows
# ---------------------------------------------------------------------------

Write-Section "Checking for file locks via Restart Manager API"

$rmSignature = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class RestartManagerLsof
{
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint pSessionHandle);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFilenames,
        uint nApplications, [In] RM_UNIQUE_PROCESS[] rgApplications, uint nServices, string[] rgsServiceNames);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo,
        [In, Out] RM_PROCESS_INFO[] rgAffectedApps, ref uint lpdwRebootReasons);

    [StructLayout(LayoutKind.Sequential)]
    public struct RM_UNIQUE_PROCESS
    {
        public int dwProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    const int RmRebootReasonNone = 0;
    const int CCH_RM_MAX_APP_NAME = 255;
    const int CCH_RM_MAX_SVC_NAME = 63;

    public enum RM_APP_TYPE
    {
        RmUnknownApp = 0, RmMainWindow = 1, RmOtherWindow = 2, RmService = 3,
        RmExplorer = 4, RmConsole = 5, RmCritical = 1000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
        public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
        public string strServiceShortName;
        public RM_APP_TYPE ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bRestartable;
    }

    public static List<int> GetLockingProcessIds(string[] paths)
    {
        var result = new List<int>();
        uint handle;
        string key = Guid.NewGuid().ToString();
        int res = RmStartSession(out handle, 0, key);
        if (res != 0) return result;

        try
        {
            res = RmRegisterResources(handle, (uint)paths.Length, paths, 0, null, 0, null);
            if (res != 0) return result;

            uint pnProcInfoNeeded = 0, pnProcInfo = 0, lpdwRebootReasons = RmRebootReasonNone;
            res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, null, ref lpdwRebootReasons);

            if (res == 234 /* ERROR_MORE_DATA */ && pnProcInfoNeeded > 0)
            {
                pnProcInfo = pnProcInfoNeeded;
                var processInfo = new RM_PROCESS_INFO[pnProcInfo];
                res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, ref lpdwRebootReasons);
                if (res == 0)
                {
                    for (int i = 0; i < pnProcInfo; i++)
                    {
                        result.Add(processInfo[i].Process.dwProcessId);
                    }
                }
            }
        }
        finally
        {
            RmEndSession(handle);
        }
        return result;
    }
}
"@

Add-Type -TypeDefinition $rmSignature -Language CSharp -ErrorAction SilentlyContinue

$lockingPids = New-Object System.Collections.Generic.HashSet[int]

if ($filesToCheck.Count -gt 0) {
    # Restart Manager works on batches; chunk to avoid overly large single calls
    $chunkSize = 200
    for ($i = 0; $i -lt $filesToCheck.Count; $i += $chunkSize) {
        $chunk = $filesToCheck.GetRange($i, [Math]::Min($chunkSize, $filesToCheck.Count - $i))
        try {
            $ids = [RestartManagerLsof]::GetLockingProcessIds([string[]]$chunk)
            foreach ($id in $ids) { [void]$lockingPids.Add($id) }
        } catch {
            Write-Warning "Restart Manager check failed for a batch of files: $($_.Exception.Message)"
        }
    }
} else {
    Write-Warning "No files found to check for locks."
}

# Exclude our own PID and its parent (running this script shouldn't flag itself)
$ownPid = $PID
[void]$lockingPids.Remove($ownPid)

$lockingProcesses = @()
foreach ($procId in $lockingPids) {
    try {
        $proc = Get-Process -Id $procId -ErrorAction Stop
        $lockingProcesses += $proc
    } catch {
        # process may have exited already
    }
}

if ($lockingProcesses.Count -gt 0) {
    Write-Host "Processes holding a lock on Claude files:" -ForegroundColor Yellow
    $lockingProcesses | Select-Object Id, ProcessName, Path, StartTime | Format-Table -AutoSize
} else {
    Write-Host "No processes currently hold a lock on the Claude files checked." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 3. Broader sweep: any lingering Claude-named / Claude-path processes
#    (covers cases where the hang isn't a file lock RM can see, e.g. a
#    zombie helper process, mutex, or named pipe)
# ---------------------------------------------------------------------------

Write-Section "Sweeping for any other lingering Claude processes"

$allProcs = Get-Process -ErrorAction SilentlyContinue
$claudeLike = $allProcs | Where-Object {
    $_.Id -ne $ownPid -and (
        $_.ProcessName -match '(?i)claude|cowork' -or
        ($_.Path -and $_.Path -match '(?i)claude|cowork')
    )
}

$candidateSet = New-Object System.Collections.Generic.List[System.Diagnostics.Process]
foreach ($p in $lockingProcesses) { $candidateSet.Add($p) }
foreach ($p in $claudeLike) {
    if (-not ($candidateSet | Where-Object { $_.Id -eq $p.Id })) {
        $candidateSet.Add($p)
    }
}

if ($candidateSet.Count -eq 0) {
    Write-Host "No lingering Claude processes found at all. The lock may be transient - try launching Claude again." -ForegroundColor Green
    exit 0
}

Write-Host ""
Write-Host "Found $($candidateSet.Count) candidate process(es):" -ForegroundColor Yellow
$candidateSet | Select-Object Id, ProcessName, Path, StartTime | Format-Table -AutoSize

# ---------------------------------------------------------------------------
# 4. Prompt before stopping anything
# ---------------------------------------------------------------------------

Write-Section "Stop processes?"

foreach ($proc in $candidateSet) {
    $label = "PID $($proc.Id) - $($proc.ProcessName)" + $(if ($proc.Path) { " ($($proc.Path))" } else { "" })
    $answer = Read-Host "Stop $label ? [y/N]"
    if ($answer -match '^(y|yes)$') {
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            Write-Host "  Stopped $label" -ForegroundColor Green
        } catch {
            Write-Warning "  Failed to stop $label - $($_.Exception.Message). Try running this script as Administrator."
        }
    } else {
        Write-Host "  Skipped $label"
    }
}

Write-Host ""
Write-Host "Done. Try launching Claude again." -ForegroundColor Cyan
