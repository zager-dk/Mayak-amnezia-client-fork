
function appName()
{
    return installer.value("Name")
}

function serviceName()
{
    return (appName() + "-service")
}

function appExecutableFileName()
{
    if (runningOnWindows()) {
        return appName() + ".exe";
    } else {
        return appName();
    }
}

function runningOnWindows()
{
    return (systemInfo.kernelType === "winnt");
}

function runningOnMacOS()
{
    return (systemInfo.kernelType === "darwin");
}

function runningOnLinux()
{
    return (systemInfo.kernelType === "linux");
}

function vcRuntimeIsInstalled()
{
    return (installer.findPath("msvcp140.dll", [installer.value("RootDir")+ "\\Windows\\System32\\"]).length !== 0)
}

// This PowerShell program is part of the signed Qt IFW script resource. It is
// intentionally embedded here: a file installed into TargetDir does not exist
// before preflight or target creation for a fresh install or an old upgrade.
var lifecycleScript = String.raw`
param([string]$Action,[string]$TargetDir,[string]$Snapshot,[string]$AllowClose,[string]$Token)
$ErrorActionPreference='Stop'
# Qt IFW forwards its parent's environment verbatim. A launcher using PowerShell
# 7 can put incompatible Security/Management modules ahead of Windows PowerShell
# 5.1. This helper uses only OS modules; isolate its child-process module search.
$env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$OutputEncoding=[Console]::OutputEncoding
$name='MayakVPN-service'
$expected=[IO.Path]::GetFullPath((Join-Path $TargetDir 'MayakVPN-service.exe'))
$preflightSnapshot=$null
$launchApp=$false
function OwnerMarker { return Join-Path (Split-Path (ActiveRunPath)) 'owned-service.json' }
function ActiveRunPath {
  $root=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'MayakVPN-InstallerState'
  if (Test-Path -LiteralPath $root) {
    $item=Get-Item -LiteralPath $root -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Unsafe installer state directory. No Mayak service was changed.'}
    $owner=(Get-Acl -LiteralPath $root).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18','S-1-5-32-544')) {throw 'Installer state directory is not administrator-owned. No Mayak service was changed.'}
  } else {New-Item -ItemType Directory -Path $root|Out-Null}
  $acl=New-Object Security.AccessControl.DirectorySecurity
  $admins=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
  $acl.SetOwner($admins); $acl.SetAccessRuleProtection($true,$false)
  foreach ($sid in @($admins,$system)) {$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))}
  Set-Acl -LiteralPath $root -AclObject $acl
  return Join-Path $root 'active-run.json'
}
function WriteActiveRun([string]$mode,[object[]]$binaries=@(),$startup=$null) {
  @{token=$Token;expected=$expected;mode=$mode;binaries=$binaries;startup=$startup}|ConvertTo-Json -Depth 5 -Compress|Set-Content -Encoding UTF8 -LiteralPath (ActiveRunPath)
}
function ReadActiveRun {
  $p=ActiveRunPath
  if (-not (Test-Path -LiteralPath $p)) {return $null}
  return Get-Content -Raw -LiteralPath $p|ConvertFrom-Json
}
function EndActiveRun {
  $x=ReadActiveRun
  if ($x -and $x.token -eq $Token -and [string]::Equals($x.expected,$expected,[StringComparison]::OrdinalIgnoreCase)) {Remove-Item -LiteralPath (ActiveRunPath) -Force}
}
function ReadOwner {
  $m=OwnerMarker
  if (-not (Test-Path -LiteralPath $m)) {return $null}
  $owner=Get-Content -Raw -LiteralPath $m|ConvertFrom-Json
  if ($owner.name -ne $name -or -not [string]::Equals([IO.Path]::GetFullPath($owner.expected),$expected,[StringComparison]::OrdinalIgnoreCase) -or [string]::IsNullOrWhiteSpace([string]$owner.token)) {throw 'The saved Mayak service ownership record does not match this installation.'}
  return $owner
}
function RequiredBinaries {
  $base=[IO.Path]::GetFullPath($TargetDir).TrimEnd('\')+'\'
  foreach ($required in @('MayakVPN.exe','MayakVPN-service.exe')) {if (-not (Test-Path -LiteralPath (Join-Path $TargetDir $required) -PathType Leaf)) {throw 'The Mayak installation is incomplete. Repair it with the full Mayak installer before uninstalling.'}}
  $pending=New-Object System.Collections.Generic.Stack[string]
  $pending.Push($TargetDir)
  $files=New-Object System.Collections.Generic.List[object]
  while ($pending.Count -gt 0) {
    $directory=Get-Item -LiteralPath ($pending.Pop()) -Force
    if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'An installation directory is a reparse point. No uninstall file operations were started.'}
    foreach ($item in @(Get-ChildItem -LiteralPath $directory.FullName -Force -ErrorAction Stop)) {
      if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'An installation path is a reparse point. No uninstall file operations were started.'}
      if ($item.PSIsContainer) {$pending.Push($item.FullName); continue}
      if (($item.Extension -in @('.exe','.dll') -and $item.Name -ne 'maintenancetool.exe') -or $item.Name -in @('qt.conf','qmldir')) {
        $p=[IO.Path]::GetFullPath($item.FullName)
        if (-not $p.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)) {throw 'An installation binary is outside the selected Mayak directory.'}
        $files.Add(@{path=$p;hash=(Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash})
      }
    }
  }
  return $files.ToArray()
}
function VerifyUninstallBinaries {
  $active=ReadActiveRun
  if (-not $active -or $active.token -ne $Token -or $active.mode -ne 'uninstall' -or -not [string]::Equals($active.expected,$expected,[StringComparison]::OrdinalIgnoreCase) -or @($active.binaries).Count -eq 0) {throw 'The uninstall integrity record is unavailable. Repair the partial uninstall with the full Mayak installer.'}
  $base=[IO.Path]::GetFullPath($TargetDir).TrimEnd('\')+'\'
  foreach ($binary in @($active.binaries)) {
    $p=[IO.Path]::GetFullPath($binary.path)
    if (-not $p.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $p -PathType Leaf)) {throw 'Partial uninstall: required Mayak files were removed. Service registration was preserved. Repair with the full Mayak installer.'}
    $item=Get-Item -LiteralPath $p -Force
    $parent=[IO.Path]::GetDirectoryName($p)
    while ($parent) {
      if ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Partial uninstall: an installation directory changed. Repair with the full Mayak installer.'}
      if ([string]::Equals($parent,$base.TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase)) {break}
      $parent=[IO.Path]::GetDirectoryName($parent)
    }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash -ne $binary.hash) {throw 'Partial uninstall: required Mayak binaries changed. Service registration was preserved. Repair with the full Mayak installer.'}
  }
}
function GetMayak {
  $s=Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
  if ($null -eq $s) { return $null }
  $p=[string]$s.PathName
  if ($p -match '^"([^"]+)"(?:\s.*)?$') {$p=$Matches[1]} elseif ($p -match '^(.+?\.exe)(?:\s.*)?$') {$p=$Matches[1]}
  try {$p=[IO.Path]::GetFullPath($p)} catch {throw 'Cannot safely resolve the existing Mayak service binary path.'}
  if (-not [string]::Equals($p,$expected,[StringComparison]::OrdinalIgnoreCase)) {throw "Existing MayakVPN-service points to '$p', not the selected Mayak directory. No service configuration was changed."}
  return $s
}
# Start-Service waits internally. ServiceController.Start issues only the request.
function RequestStart {
  Add-Type -AssemblyName System.ServiceProcess -ErrorAction Stop
  $controller=New-Object System.ServiceProcess.ServiceController($name)
  try {$controller.Start()} finally {$controller.Dispose()}
}
function StartupMode($s) {
  $delayed=(Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$name) -Name DelayedAutoStart -ErrorAction SilentlyContinue).DelayedAutoStart
  if ($s.StartMode -eq 'Auto') {if ($delayed -eq 1) {return 'delayed-auto'}; return 'auto'}
  if ($s.StartMode -eq 'Manual') {return 'demand'}
  if ($s.StartMode -eq 'Disabled') {return 'disabled'}
  throw 'Unknown Mayak service startup mode. No service configuration was changed.'
}
function SetStartupMode([string]$mode) {
  if ($mode -notin @('auto','delayed-auto','demand','disabled')) {throw 'Invalid saved Mayak service startup mode.'}
  $s=GetMayak; if ($null -eq $s) {throw 'Mayak service disappeared during installation.'}
  sc.exe config $name 'start=' $mode|Out-Null
  if ($LASTEXITCODE -ne 0) {throw 'Could not set Mayak service startup mode.'}
}
function RestoreStartup {
  $active=ReadActiveRun
  if (-not $active -or $active.token -ne $Token -or -not [string]::Equals($active.expected,$expected,[StringComparison]::OrdinalIgnoreCase)) {throw 'Missing Mayak installer transaction; service startup was not changed.'}
  if ($active.startup) {SetStartupMode ([string]$active.startup)}
}
function StopForReplacement {
  # Older versions crash on shutdown. Disable starts temporarily so SCM recovery
  # cannot relaunch the old binary while files are replaced. Recovery actions,
  # account and dependencies remain intact; the saved mode is restored below.
  SetStartupMode 'disabled'
  try {Stop-Service -Name $name -NoWait -ErrorAction Stop} catch {
    $cause=$_.Exception
    while ($cause.InnerException) {$cause=$cause.InnerException}
    if ($cause -isnot [ComponentModel.Win32Exception] -or $cause.NativeErrorCode -notin @(109,1062)) {throw}
  }
  WaitStopped
}
function WaitStopped {
  for ($poll=0; $poll -lt 120; $poll++) {
    # A missing result is not proof that SCM stopped the service. Query errors
    # (including access denied and RPC failures) must abort before file changes.
    $s=Get-Service -Name $name -ErrorAction Stop
    if ($null -eq $s) {throw 'Windows Service Control Manager returned no status for MayakVPN-service. Installation was not started.'}
    if ($s.Status -eq 'Stopped') {return}
    Start-Sleep -Milliseconds 250
  }
  throw 'Timed out waiting for MayakVPN-service to stop. Installation was not started.'
}
function WaitRunning {
  for ($poll=0; $poll -lt 120; $poll++) {
    $s=Get-Service -Name $name -ErrorAction Stop
    if ($s.Status -eq 'Running') {return}
    Start-Sleep -Milliseconds 250
  }
  throw 'Timed out waiting for MayakVPN-service to return to Running.'
}
function GetMayakProcesses {
  $app=[IO.Path]::GetFullPath((Join-Path $TargetDir 'MayakVPN.exe'))
  $items=@(Get-CimInstance Win32_Process -Filter "Name='MayakVPN.exe'" -ErrorAction Stop)
  $matchingProcesses=New-Object System.Collections.Generic.List[object]
  foreach ($p in $items) {
    if ([string]::IsNullOrWhiteSpace([string]$p.ExecutablePath)) {throw 'Windows could not verify the executable path of a MayakVPN process. No files were changed.'}
    try {$processPath=[IO.Path]::GetFullPath([string]$p.ExecutablePath)} catch {throw 'Windows returned an invalid MayakVPN process path. No files were changed.'}
    if ([string]::Equals($processPath,$app,[StringComparison]::OrdinalIgnoreCase)) {$matchingProcesses.Add($p)}
  }
  return $matchingProcesses.ToArray()
}
try {
 switch ($Action) {
  {$_ -eq 'preflight' -or $_ -eq 'uninstall-preflight'} {
    $s=GetMayak
    # Validate an existing ownership record before file operations on full EXE
    # installs too. An older same-target Mayak with no record remains supported.
    $owner=ReadOwner
    if ($null -ne $s -and $owner -and $owner.createdByRun -and $s.Description -notlike ('*QtIFW-owner:'+$owner.token+'*')) {throw 'Mayak service ownership changed. No application files were changed.'}
    if ($Action -eq 'uninstall-preflight' -and $null -ne $s) {
      if ($null -eq $owner) {throw 'Mayak service ownership is unknown. Use the full Mayak installer before uninstalling; no application files were removed.'}
    }
    $running=@(GetMayakProcesses)
    $appWasRunning=$running.Count -gt 0
    $wasRunning=$null -ne $s -and $s.State -eq 'Running'
    $capturedSnapshot=@{exists=($null -ne $s);wasRunning=$wasRunning;appWasRunning=$appWasRunning;expected=$expected}
    $binaries=@()
    if ($Action -eq 'uninstall-preflight') {$binaries=@(RequiredBinaries)}
    $startup=if ($null -ne $s) {StartupMode $s} else {$null}
    WriteActiveRun $(if ($Action -eq 'uninstall-preflight') {'uninstall'} else {'install'}) $binaries $startup
    $preflightSnapshot=$capturedSnapshot
    if ($appWasRunning) {
      if ($AllowClose -ne 'true') {throw 'MayakVPN is still open. The background update will not close it; close MayakVPN and retry.'}
      $launchApp=$true
      try {
        foreach ($p in $running) {Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop}
        $until=[DateTime]::UtcNow.AddSeconds(10)
        do {$remaining=@(GetMayakProcesses); if ($remaining.Count -eq 0) {break}; Start-Sleep -Milliseconds 200} while ([DateTime]::UtcNow -lt $until)
        if ($remaining.Count -gt 0) {throw 'Timed out waiting for MayakVPN to close.'}
      } catch {
        throw
      }
    }
    if ($null -ne $s) {StopForReplacement}
    $preflightSnapshot|ConvertTo-Json -Compress
  }
  'finish' {
    $s=GetMayak; $created=$false; $markerCreated=$false
    if ($null -eq $s) {
      sc.exe create $name 'binPath=' ('"'+$expected+'"') 'start=' 'auto' 'depend=' 'BFE/nsi'|Out-Null
      if ($LASTEXITCODE -ne 0) {throw 'Could not register the new MayakVPN-service.'}
      $created=$true
      $description='Mayak VPN Service (QtIFW-owner:'+$Token+')'
      sc.exe description $name $description|Out-Null
      if ($LASTEXITCODE -ne 0) {try {sc.exe delete $name|Out-Null} catch {}; throw 'Could not mark the new MayakVPN-service as installer-owned.'}
      sc.exe failure $name 'reset=' '100' 'actions=' 'restart/2000/restart/2000/restart/2000'|Out-Null
      if ($LASTEXITCODE -ne 0) {try {sc.exe delete $name|Out-Null} catch {}; throw 'Could not configure recovery for the new MayakVPN-service.'}
      $m=OwnerMarker
      try {New-Item -ItemType Directory -Force -Path (Split-Path $m)|Out-Null; @{name=$name;expected=$expected;token=$Token;createdByRun=$true}|ConvertTo-Json -Compress|Set-Content -Encoding UTF8 -Path $m; $markerCreated=$true} catch {try {sc.exe delete $name|Out-Null} catch {}; throw}
    } else {
      $m=OwnerMarker
      if (Test-Path -LiteralPath $m) {
        $owner=Get-Content -Raw -LiteralPath $m|ConvertFrom-Json
        if ($owner.name -ne $name -or -not [string]::Equals([IO.Path]::GetFullPath($owner.expected),$expected,[StringComparison]::OrdinalIgnoreCase) -or [string]::IsNullOrWhiteSpace([string]$owner.token)) {throw 'The existing Mayak service ownership record does not match this installation. No service configuration was changed.'}
      } else {
        New-Item -ItemType Directory -Force -Path (Split-Path $m)|Out-Null
        @{name=$name;expected=$expected;token=$Token;createdByRun=$false}|ConvertTo-Json -Compress|Set-Content -Encoding UTF8 -Path $m
        $markerCreated=$true
      }
    }
    try {
      RestoreStartup
      # A deliberately disabled existing service stays disabled and stopped.
      if ((GetMayak).StartMode -eq 'Disabled') {break}
      $s=GetMayak; if ($s.State -ne 'Running') {RequestStart}
      WaitRunning
    } catch {
      if ($created) {try {$s=Get-Service -Name $name -ErrorAction SilentlyContinue; if ($s -and $s.Status -ne 'Stopped') {Stop-Service -Name $name -NoWait -ErrorAction Stop; WaitStopped}; sc.exe delete $name|Out-Null; if ($LASTEXITCODE -eq 0) {Remove-Item -LiteralPath (OwnerMarker) -Force -ErrorAction SilentlyContinue}} catch {}}
      elseif ($markerCreated) {Remove-Item -LiteralPath (OwnerMarker) -Force -ErrorAction SilentlyContinue}
      throw
    }
  }
  {$_ -eq 'rollback' -or $_ -eq 'uninstall-rollback'} {
    if ($Action -eq 'uninstall-rollback') {VerifyUninstallBinaries}
    RestoreStartup
    if ($Snapshot) {$x=$Snapshot|ConvertFrom-Json; $launchApp=[bool]$x.appWasRunning; if ($x.exists) {$s=GetMayak; if ($null -eq $s) {throw 'The original Mayak service is missing; its configuration was not recreated.'}; if ($x.wasRunning -and $s.State -ne 'Running') {RequestStart; WaitRunning} elseif (-not $x.wasRunning -and $s.State -ne 'Stopped') {Stop-Service -Name $name -NoWait -ErrorAction Stop; WaitStopped}}}
    EndActiveRun
    @{launchApp=$launchApp}|ConvertTo-Json -Compress
  }
  'remove-created' {
    $active=ReadActiveRun
    if (-not $active) {throw 'The active installer transaction record is missing. No service registration was removed.'}
    if ($active.token -ne $Token -or $active.mode -eq 'uninstall') {break}
    if ($active.mode -ne 'install' -or -not [string]::Equals($active.expected,$expected,[StringComparison]::OrdinalIgnoreCase)) {throw 'The active installer transaction does not match this Mayak installation.'}
    # Undo precedes framework file rollback. Stop a matching existing service,
    # but remove registration only when this exact installation created it.
    $s=GetMayak
    if ($null -ne $s -and $s.State -ne 'Stopped') {Stop-Service -Name $name -NoWait -ErrorAction Stop; WaitStopped}
    $m=OwnerMarker
    if (Test-Path -LiteralPath $m) {$x=Get-Content -Raw -LiteralPath $m|ConvertFrom-Json; if ($x.token -eq $Token -and $x.createdByRun -and $x.name -eq $name -and [string]::Equals([IO.Path]::GetFullPath($x.expected),$expected,[StringComparison]::OrdinalIgnoreCase)) {$s=GetMayak; if ($null -ne $s) {if ($s.Description -notlike ('*QtIFW-owner:'+$Token+'*')) {throw 'Service ownership could not be verified; refusing to remove it.'}; if ($s.State -ne 'Stopped') {Stop-Service -Name $name -NoWait -ErrorAction Stop; WaitStopped}; sc.exe delete $name|Out-Null; if ($LASTEXITCODE -ne 0) {throw 'Could not remove the service created by this installer.'}}; Remove-Item -LiteralPath $m -Force} elseif ($x.token -eq $Token -and -not $x.createdByRun -and $x.name -eq $name -and [string]::Equals([IO.Path]::GetFullPath($x.expected),$expected,[StringComparison]::OrdinalIgnoreCase)) {Remove-Item -LiteralPath $m -Force}}
  }
  'uninstall-owned' {
    $m=OwnerMarker
    if (-not (Test-Path -LiteralPath $m) -and $null -ne (GetMayak)) {throw 'The service ownership record disappeared. No service registration was removed.'}
    if (Test-Path -LiteralPath $m) {
      $owner=Get-Content -Raw -LiteralPath $m|ConvertFrom-Json
      if ($owner.name -ne $name -or -not [string]::Equals([IO.Path]::GetFullPath($owner.expected),$expected,[StringComparison]::OrdinalIgnoreCase) -or [string]::IsNullOrWhiteSpace([string]$owner.token)) {throw 'The saved Mayak service ownership record does not match this installation; refusing to remove the service.'}
      $s=GetMayak
      if ($null -ne $s) {
        if ($owner.createdByRun -and $s.Description -notlike ('*QtIFW-owner:'+$owner.token+'*')) {throw 'Service ownership could not be verified; refusing to remove it.'}
        if ($s.State -ne 'Stopped') {Stop-Service -Name $name -NoWait -ErrorAction Stop; WaitStopped}
        sc.exe delete $name|Out-Null; if ($LASTEXITCODE -ne 0) {throw 'Could not remove the installer-owned MayakVPN-service.'}
      }
      Remove-Item -LiteralPath $m -Force
    }
    EndActiveRun
  }
  'gui-needed' {@{launchApp=(@(GetMayakProcesses).Count -eq 0)}|ConvertTo-Json -Compress}
  'end' {EndActiveRun}
 }
 exit 0
} catch {
  $message=$_.Exception.Message
  [Console]::Error.WriteLine('Mayak setup '+$Action+': '+$_.ToString())
  try { $log=Join-Path (Split-Path (ActiveRunPath)) 'last-error.txt'; ("Action="+$Action+[Environment]::NewLine+$message)|Set-Content -Encoding UTF8 -LiteralPath $log } catch {}
  @{error=$message;launchApp=$launchApp;snapshot=$preflightSnapshot}|ConvertTo-Json -Compress; exit 1
}
`;

var lifecycleToken = new Date().getTime() + "-" + Math.random().toString(36).substring(2);

function lifecycleCommand(action, target, snapshot, allowClose)
{
    function quote(value) { return "'" + String(value || "").replace(/'/g, "''") + "'"; }
    var raw = "& { " + lifecycleScript + " } " + quote(action) + " " + quote(target) + " " + quote(snapshot) + " " + quote(allowClose ? "true" : "false") + " " + quote(lifecycleToken);
    // Qt IFW replaces @...@ variables in every process argument. PowerShell uses
    // @() / @{} throughout this program; encode the WHOLE command before IFW sees it.
    var bytes = unescape(encodeURIComponent(raw));
    var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var encoded = "";
    for (var i = 0; i < bytes.length; i += 3) {
        var a = bytes.charCodeAt(i), hasB = i + 1 < bytes.length, hasC = i + 2 < bytes.length;
        var b = hasB ? bytes.charCodeAt(i + 1) : 0, c = hasC ? bytes.charCodeAt(i + 2) : 0;
        encoded += alphabet[a >> 2] + alphabet[((a & 3) << 4) | (b >> 4)]
                 + (hasB ? alphabet[((b & 15) << 2) | (c >> 6)] : "=") + (hasC ? alphabet[c & 63] : "=");
    }
    return "& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + encoded + "'))))";
}

function windowsPowerShell()
{
    var root = installer.environmentVariable("SystemRoot") || (installer.value("RootDir") + "Windows");
    return root.replace(/\\/g, "/") + "/System32/WindowsPowerShell/v1.0/powershell.exe";
}

function runLifecycle(action, target, snapshot, allowClose)
{
    return installer.execute(windowsPowerShell(), ["-NoLogo", "-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                                               lifecycleCommand(action, target, snapshot, allowClose)]);
}

function lifecycleResult(result)
{
    if (!result || result.length < 2) return {ok: false, payload: {error: "Не удалось запустить системный PowerShell. Закройте установщик и запустите его от имени администратора."}};
    var payload = {};
    try { payload = JSON.parse(String(result[0] || "{}")); } catch (error) { payload.error = String(result[0] || error); }
    return { ok: result.length > 1 && Number(result[1]) === 0, payload: payload };
}

function recoveryNotice(error)
{
    QMessageBox.critical("Mayak VPN", "Mayak VPN recovery could not finish",
        "The existing service configuration was not recreated or reset. " + String(error || "The authorized Windows session is unavailable.") +
        " Restart Windows if necessary, then use the full Mayak installer from the app or contact support. Do not remove another VPN service.");
}

function launchUserGui(target, requested)
{
    if (!requested) return;
    installer.dropAdminRights();
    if (installer.hasAdminRights()) {
        // Leave application launch to the normal desktop shortcut after elevated setup.
        return;
    }
    try {
        var needed = lifecycleResult(runLifecycle("gui-needed", target, "", false));
        if (!needed.ok) { recoveryNotice(needed.payload.error); return; }
        if (needed.payload.launchApp && !installer.executeDetached(target + "/MayakVPN.exe", [], target))
            recoveryNotice("Open Mayak normally from your desktop; the user application could not be started.");
    } catch (error) { recoveryNotice(String(error)); }
}

function beginLifecycle(instance, uninstall)
{
    var target = installer.value("TargetDir");
    var passed = false;
    // Both ordinary launch (with UAC) and Run as administrator are supported.
    instance._mayakStartedElevated = installer.hasAdminRights();
    instance._mayakPreflightTarget = target;
    try {
        if (!installer.gainAdminRights()) throw new Error("Windows administrator permission was not granted.");
        instance._mayakBrokerAuthorized = true;
        var result = lifecycleResult(runLifecycle(uninstall ? "uninstall-preflight" : "preflight", target, "", true));
        if (result.ok) {
            instance._mayakPreflightSnapshot = JSON.stringify(result.payload);
            passed = true;
        }
        else {
            if (result.payload.snapshot) instance._mayakPreflightSnapshot = JSON.stringify(result.payload.snapshot);
            if (instance._mayakPreflightSnapshot) restoreLifecycle(instance);
            QMessageBox.critical("Mayak VPN", "Mayak VPN setup could not start", String(result.payload.error || "Windows preflight failed. No application files were changed."));
            installer.interrupt();
        }
    } catch (error) {
        QMessageBox.critical("Mayak VPN", "Mayak VPN setup could not start", String(error) + " No application files were changed.");
        if (instance._mayakBrokerAuthorized && !instance._mayakPreflightSnapshot) recoveryNotice(String(error));
        installer.interrupt();
    } finally { installer.dropAdminRights(); }
    return passed;
}

function restoreLifecycle(instance)
{
    if (!instance._mayakPreflightSnapshot || instance._mayakRecoveryAttempted) return;
    instance._mayakRecoveryAttempted = true;
    var intent = false;
    try { intent = !installer.isUninstaller() && !!JSON.parse(instance._mayakPreflightSnapshot).appWasRunning; } catch (error) {}
    try {
        if (!instance._mayakBrokerAuthorized) throw new Error("No prior Windows authorization session exists.");
        // Qt IFW 4.7 drop only deactivates RemoteClient. The authorized broker is
        // retained until core destruction; this activates that same session.
        if (!installer.gainAdminRights()) throw new Error("The previously authorized Windows session is unavailable.");
        var result = lifecycleResult(runLifecycle(installer.isUninstaller() ? "uninstall-rollback" : "rollback", instance._mayakPreflightTarget, instance._mayakPreflightSnapshot, false));
        if (!result.ok) throw new Error(result.payload.error || "The original Mayak service state could not be restored.");
        intent = !!result.payload.launchApp;
        instance._mayakRecovered = true;
    } catch (error) { recoveryNotice(String(error)); }
    finally { installer.dropAdminRights(); }
    launchUserGui(instance._mayakPreflightTarget, intent);
}

function Component()
{
    component.loaded.connect(this, Component.prototype.componentLoaded);
    installer.installationStarted.connect(this, Component.prototype.installationStarted);
    installer.installationFinished.connect(this, Component.prototype.installationCompleted);
    installer.installationFinished.connect(this, Component.prototype.installationFinishedPageIsShown);
    installer.uninstallationStarted.connect(this, Component.prototype.uninstallationStarted);
    installer.uninstallationFinished.connect(this, Component.prototype.uninstallationCompleted);
    installer.statusChanged.connect(this, Component.prototype.lifecycleStatusChanged);
    installer.finishButtonClicked.connect(this, Component.prototype.installationFinished);
}

Component.prototype.installationStarted = function()
{
    if (!runningOnWindows()) return;
    if (installer.isUpdater() || installer.isPackageManager()) {
        QMessageBox.critical("Mayak VPN", "Use the full Mayak installer", "Online maintenance updates are not supported in this release. Use the verified full installer offered by the Mayak app, or download that full installer manually.");
        installer.interrupt();
        return;
    }
    this._mayakRunAuthorized = beginLifecycle(this, false);
    if (!this._mayakRunAuthorized) installer.interrupt();
}

Component.prototype.uninstallationStarted = function()
{
    if (!runningOnWindows() || !installer.isUninstaller()) return;
    this._mayakRunAuthorized = beginLifecycle(this, true);
    this._mayakUninstallBlocked = !this._mayakRunAuthorized;
    if (this._mayakUninstallBlocked) installer.interrupt();
}

Component.prototype.lifecycleStatusChanged = function(status)
{
    if (status === QInstaller.Canceled) {
        this._mayakCancelPending = true;
        // Framework completion restores the captured service state after rollback.
    }
    // Qt IFW 4.7 sets Running after uninstallationStarted. Preserve a denied
    // preflight across that reset, before runUndoOperations checks cancellation.
    if (runningOnWindows() && installer.isUninstaller() && this._mayakUninstallBlocked && status === QInstaller.Running)
        installer.interrupt();
}

Component.prototype.installationCompleted = function()
{
    if (!runningOnWindows() || !this._mayakPreflightSnapshot) return;
    if (installer.status !== QInstaller.Success) { restoreLifecycle(this); return; }
    try {
        if (!this._mayakBrokerAuthorized || !installer.gainAdminRights()) throw new Error("The authorized Windows session is unavailable.");
        var result = lifecycleResult(runLifecycle("end", this._mayakPreflightTarget, "", false));
        if (!result.ok) throw new Error(result.payload.error || "Installer state cleanup failed.");
    } catch (error) { recoveryNotice(String(error)); installer.interrupt(); }
    finally { installer.dropAdminRights(); }
}

Component.prototype.uninstallationCompleted = function()
{
    if (!runningOnWindows() || !this._mayakPreflightSnapshot) return;
    if (installer.status !== QInstaller.Success) { restoreLifecycle(this); return; }
    try {
        if (!this._mayakBrokerAuthorized || !installer.gainAdminRights()) throw new Error("The authorized Windows session is unavailable.");
        var result = lifecycleResult(runLifecycle("uninstall-owned", this._mayakPreflightTarget, "", false));
        if (!result.ok) throw new Error(result.payload.error || "The owned Mayak service could not be removed.");
    } catch (error) { recoveryNotice(String(error)); installer.interrupt(); }
    finally { installer.dropAdminRights(); }
}

Component.prototype.componentLoaded = function ()
{
    if (!runningOnWindows()) return;
    if (installer.isCommandLineInstance() || (!installer.isInstaller() && !installer.isUninstaller())) {
        installer.setCanceled();
        return;
    }
    installer.setDefaultPageVisible(QInstaller.PerformInstallation, true);
}

Component.prototype.installationFinishedPageIsShown = function()
{
    if (!runningOnWindows() && installer.isInstaller() && installer.status === QInstaller.Success) {
        gui.clickButton(buttons.FinishButton);
    }
}

Component.prototype.createOperations = function()
{
    component.createOperations();

    if (runningOnWindows()) {

        component.addOperation("CreateShortcut", "@TargetDir@/" + appExecutableFileName(),
                               QDesktopServices.storageLocation(QDesktopServices.DesktopLocation) + "/" + appName() + ".lnk",
                               "workingDirectory=@TargetDir@", "iconPath=@TargetDir@\\" + appExecutableFileName(), "iconId=0");


        component.addElevatedOperation("CreateShortcut", "@TargetDir@/" + appExecutableFileName(),
                                       installer.value("AllUsersStartMenuProgramsPath") + "/" + appName() + ".lnk",
                                       "workingDirectory=@TargetDir@", "iconPath=@TargetDir@\\" + appExecutableFileName(), "iconId=0");

        if (!vcRuntimeIsInstalled()) {
            var vcRedistFileName = (systemInfo.currentCpuArchitecture.search("64") < 0) ? "vc_redist.x86.exe"
                                                                                       : "vc_redist.x64.exe";
            if (installer.findPath(vcRedistFileName, [installer.value("TargetDir").replace(/\//g, '\\')]).length !== 0) {
                component.addElevatedOperation("Execute", "@TargetDir@\\" + vcRedistFileName, "/install", "/quiet", "/norestart", "/log", "vc_redist.log");
            } else {
                console.log(vcRedistFileName + " is not bundled, relying on the application-local MSVC runtime");
            }
        } else {
            console.log("Microsoft Visual C++ Redistributable already installed");
        }


        var targetForOperation = installer.value("TargetDir");
        var lifecycle = lifecycleCommand("finish", targetForOperation, "");
        var undoLifecycle = lifecycleCommand("remove-created", targetForOperation, "");
        var failureMessage = "errormessage=Не удалось запустить службу Маяка. Причина сохранена в журнале установки. Нажмите «Отмена» для восстановления.";
        // IFW splits at UNDOEXECUTE before parsing options: both halves need
        // their own error text and stderr capture.
        component.addElevatedOperation("Execute", [windowsPowerShell(), "-NoLogo", "-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", lifecycle, failureMessage, "showStandardError"],
                                       "UNDOEXECUTE", [windowsPowerShell(), "-NoLogo", "-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", undoLifecycle, failureMessage, "showStandardError"]);
										
    } else if (runningOnMacOS()) {
        component.addElevatedOperation("Execute", "@TargetDir@/post_install.sh", "UNDOEXECUTE", "@TargetDir@/post_uninstall.sh");
    } else if (runningOnLinux()) {
        component.addElevatedOperation("Execute", "bash", "@TargetDir@/post_install.sh", "UNDOEXECUTE", "bash", "@TargetDir@/post_uninstall.sh");
    }
}

Component.prototype.installationFinished = function()
{
    var command = "";
    var args = [];

    if ((installer.status === QInstaller.Success) && (installer.isInstaller() || installer.isUpdater())) {

        if (runningOnWindows()) {
            if (installer.isInstaller() && this._mayakPreflightSnapshot)
                launchUserGui(this._mayakPreflightTarget, true);
            return;
        }

        if (!installer.gainAdminRights()) {
            console.log("Fatal error! Cannot get admin rights!")
            return
        }

        if (runningOnMacOS()) {
            command = "/Applications/" + appName() + ".app/Contents/MacOS/" + appName();
        } else if (runningOnLinux()) {
	    command = "@TargetDir@/client/" + appName();
	}

        installer.dropAdminRights()

        processStatus = installer.executeDetached(command, args, installer.value("TargetDir"));
    }
}
