<#
.SYNOPSIS
FileShareToolkit Portable v3.2

.DESCRIPTION
Portable, local-first Windows file share discovery and NTFS permission audit tool.

No installer.
No SQLite.
No external modules.
No PowerShell Gallery dependency.
No IIS or permanent web server.
Optional temporary localhost endpoint for saving dashboard config changes.
No database engine.

Output:
- data.json for browser dashboard
- Dashboard.html with embedded JavaScript
- Dashboard export buttons for complete CSV, Excel-compatible XLS, and PDF/print
- Optional separate CSV files when -ExportCsvFiles is used

.DESIGNED FOR
- Running locally on a Windows file server
- Running as local admin or dedicated svc_fileshareaudit account
- File share cleanup
- NetApp migration planning
- Robocopy command generation

.EXAMPLE
.\Invoke-FileShareToolkit_Portable_v3_2.ps1 `
-OutputPath C:\Temp\ShareAudit `
-MaxAclDepth 0 `
-SkipSizeCalculation `
-SkipSharePermissions `
-TargetServer server

.EXAMPLE
.\Invoke-FileShareToolkit_Portable_v3_2.ps1 `
-OutputPath C:\Temp\ShareAudit `
-MaxAclDepth 1 `
-TargetServer server `
-OpenDashboard

.EXAMPLE
.\Invoke-FileShareToolkit_Portable_v3_2.ps1 `
-OutputPath C:\Temp\ShareAudit `
-MaxAclDepth 1 `
-CentralJsonPath \\auditserver\ShareAudit\Json

.EXAMPLE
.\Invoke-FileShareToolkit_Portable_v3_2.ps1 `
-GenerateCentralDashboard `
-CentralJsonPath \\auditserver\ShareAudit\Json `
-OpenDashboard

.EXAMPLE
.\Invoke-FileShareToolkit_Portable_v3_2.ps1 `
-GenerateCentralDashboard `
-CentralJsonPath \\auditserver\ShareAudit\Json `
-GitHubPagesPath .\docs

.EXAMPLE
.\Invoke-FileShareToolkit_Portable_v3_2.ps1 `
-OutputPath C:\Temp\ShareAudit `
-ConfigPath .\config\targets.json `
-CentralJsonPath \\auditserver\ShareAudit\Json `
-OpenDashboard

.EXAMPLE
.\Invoke-FileShareToolkit_Portable_v3_2.ps1 `
-OutputPath C:\Temp\ShareAudit `
-MaxAclDepth 1 `
-RobocopyDiagnosticDestinationRoot \\netapp\migrationtest\RobocopyDiagnostics `
-OpenDashboard
#>

[CmdletBinding()]
param(
[string]$OutputPath = "C:\Temp\ShareAudit",

[string]$ConfigPath,

[int]$MaxAclDepth = 0,

[switch]$IncludeAdminShares,

[switch]$SkipSizeCalculation,

[switch]$SkipSharePermissions,

[switch]$ExportCsvFiles,

[string]$TargetServer = "TARGETSERVER",

[int]$RobocopyThreads = 8,

[string]$RobocopyDiagnosticDestinationRoot,

[int]$MaxAccessDiagnosticGroups = 50,

[int]$MaxDiagnosticFileSamplesPerFolder = 3,

[switch]$SkipAccessDiagnostics,

[string]$CentralJsonPath,

[switch]$GenerateCentralDashboard,

[string]$CentralDashboardPath,

[string]$GitHubPagesPath,

[switch]$KeepCentralRunHistory,

[switch]$OpenDashboard
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Continue"

$Server = $env:COMPUTERNAME
$RunId = Get-Date -Format "yyyyMMdd_HHmmss"
$ScriptPath = $null
$psCommandPathVariable = Get-Variable -Name PSCommandPath -ErrorAction SilentlyContinue
if ($null -ne $psCommandPathVariable) {
$ScriptPath = [string]$psCommandPathVariable.Value
}
if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
$ScriptPath = [string]$MyInvocation.MyCommand.Path
}

if ($GenerateCentralDashboard -and [string]::IsNullOrWhiteSpace($CentralJsonPath)) {
throw "-CentralJsonPath is required when using -GenerateCentralDashboard."
}

if ($GenerateCentralDashboard) {
$RunRoot = $CentralJsonPath
$LogPath = Join-Path $RunRoot ("CentralDashboard_{0}.log" -f $RunId)
}
else {
$RunRoot = Join-Path $OutputPath "Run_$RunId"
$LogPath = Join-Path $RunRoot "FileShareToolkit.log"
}

New-Item -ItemType Directory -Path $RunRoot -Force | Out-Null

function Write-Log {
param(
[string]$Message,
[string]$Level = "INFO"
)

$line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
Write-Host $line
Add-Content -Path $LogPath -Value $line
}

function Export-CsvSafe {
param(
[object[]]$Data,
[string]$Name
)

if ($null -eq $Data) { $Data = @() }

$path = Join-Path $RunRoot $Name
$Data | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
return $path
}

function Test-AdminShare {
param([string]$Name)

if ($Name -match '^[A-Z]\$$') { return $true }
if ($Name -in @("ADMIN$","IPC$","PRINT$")) { return $true }
return $false
}

function Get-Depth {
param(
[string]$Root,
[string]$Current
)

if ($Current.Length -lt $Root.Length) { return 0 }

$relative = $Current.Substring($Root.Length).Trim('\')
if ([string]::IsNullOrWhiteSpace($relative)) { return 0 }

return ($relative -split '\\').Count
}

function Get-AceRiskFlags {
param(
[object]$Acl,
[object]$Ace
)

$flags = New-Object System.Collections.Generic.List[string]
$identity = [string]$Ace.IdentityReference.Value

if ($Acl.AreAccessRulesProtected) { $flags.Add("BrokenInheritance") }
if ($identity -match '^S-\d-\d+') { $flags.Add("OrphanedSID") }
if ($identity -match 'Everyone|Authenticated Users|BUILTIN\\Users') { $flags.Add("BroadPrincipal") }
if ([string]$Ace.AccessControlType -eq "Deny") { $flags.Add("DenyACE") }
if ([string]$Ace.FileSystemRights -match "FullControl") { $flags.Add("FullControlACE") }

if ($identity -match '\\') {
$short = ($identity -split '\\')[-1]
if ($short -notmatch '^(Domain Admins|Administrators|SYSTEM|Users|Authenticated Users|Everyone|CREATOR OWNER)$' -and
$short -notmatch '^(GG_|DL_|AG_|FS_|GRP_|SEC_|SG_|DLG_)') {
$flags.Add("PossibleDirectUserOrNonStandardGroup")
}
}

return (($flags | Sort-Object -Unique) -join ";")
}

function Get-AclRemediationAdvice {
param(
[string]$RiskFlags,
[string]$ScanStatus,
[string]$Error,
[string]$IdentityReference,
[string]$AccessControlType,
[string]$FileSystemRights
)

$advice = New-Object System.Collections.Generic.List[string]
$flags = [string]$RiskFlags
$errorText = [string]$Error

if ($ScanStatus -eq "Failed" -or $flags -match "AclReadDenied|EnumerationFailed" -or $errorText -match "Access is denied|UnauthorizedAccess|permission") {
$advice.Add("Access denied: do not reset ACLs. First back up permissions with icacls /save. Run PowerShell elevated or as the file server local admin/SYSTEM. If still blocked, take ownership only on the affected object, preferably to the Administrators group, then add a temporary admin ACE; this preserves the existing DACL instead of replacing it.")
}

if ($flags -match "PathNotFound") {
$advice.Add("Path not found: verify the share path, mount point, DFS target, and service account visibility before changing permissions.")
}

if ($flags -match "OrphanedSID") {
$advice.Add("Orphaned SID: identify whether the SID maps to a deleted or migrated account. If it is obsolete, remove only that ACE after an ACL backup; if it belongs to a migrated identity, replace it with the correct current group.")
}

if ($flags -match "BrokenInheritance") {
$advice.Add("Broken inheritance: review why inheritance was disabled before enabling it. If the folder should follow the parent model, document explicit ACEs, back up ACLs, then re-enable inheritance and convert or remove duplicate explicit ACEs deliberately.")
}

if ($flags -match "BroadPrincipal") {
$advice.Add("Broad principal: replace Everyone, Authenticated Users, or BUILTIN\\Users with the smallest approved domain group. Validate share permissions and NTFS permissions together before removal.")
}

if ($flags -match "DenyACE") {
$advice.Add("Deny ACE: check whether the deny is intentional. Prefer removing the user/group from an allow group rather than relying on deny ACEs, because deny entries override allows and often cause troubleshooting issues.")
}

if ($flags -match "FullControlACE") {
$advice.Add("Full Control: reduce to Modify or Read/Execute for normal users where possible. Keep Full Control limited to service/admin groups that own the data management process.")
}

if ($flags -match "PossibleDirectUserOrNonStandardGroup") {
$advice.Add("Direct user or non-standard group: move access to a named role-based group, then remove the direct user ACE after validation. This keeps future cleanup and ownership transfer manageable.")
}

if ($advice.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($flags)) {
$advice.Add("Review this ACL manually. Back up ACLs before changing permissions and prefer additive test changes over replacing the whole DACL.")
}

return (($advice | Sort-Object -Unique) -join " ")
}

function Get-FolderStats {
param([string]$Path)

$result = [ordered]@{
SizeBytes = $null
SizeGB = $null
FileCount = $null
FolderCount = $null
Error = $null
}

try {
$files = Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue
$folders = Get-ChildItem -LiteralPath $Path -Recurse -Force -Directory -ErrorAction SilentlyContinue

$sizeBytes = ($files | Measure-Object -Property Length -Sum).Sum
$result.SizeBytes = $sizeBytes

if ($null -ne $sizeBytes) {
$result.SizeGB = [math]::Round($sizeBytes / 1GB, 2)
}

$result.FileCount = ($files | Measure-Object).Count
$result.FolderCount = ($folders | Measure-Object).Count
}
catch {
$result.Error = $_.Exception.Message
}

return [pscustomobject]$result
}

function Get-LocalShares {
Write-Log "Discovering local SMB shares on $Server"

try {
$shares = Get-SmbShare -ErrorAction Stop
}
catch {
Write-Log "Get-SmbShare failed. Run PowerShell as Administrator. Error: $($_.Exception.Message)" "ERROR"
return @()
}

if (-not $IncludeAdminShares) {
$shares = $shares | Where-Object {
$_.Special -eq $false -and -not (Test-AdminShare -Name $_.Name)
}
}

$rows = New-Object System.Collections.Generic.List[object]

foreach ($share in $shares) {
$sizeBytes = $null
$sizeGB = $null
$fileCount = $null
$folderCount = $null
$sizeError = $null

if (-not $SkipSizeCalculation) {
Write-Log "Calculating size for share $($share.Name). This can take time."
$stats = Get-FolderStats -Path $share.Path
$sizeBytes = $stats.SizeBytes
$sizeGB = $stats.SizeGB
$fileCount = $stats.FileCount
$folderCount = $stats.FolderCount
$sizeError = $stats.Error
}

$rows.Add([pscustomobject]@{
Server = $Server
ShareName = $share.Name
SharePath = $share.Path
UNCPath = "\\$Server\$($share.Name)"
Description = $share.Description
ShareState = [string]$share.ShareState
FolderEnumerationMode = [string]$share.FolderEnumerationMode
CachingMode = [string]$share.CachingMode
EncryptData = [string]$share.EncryptData
ContinuouslyAvailable = [string]$share.ContinuouslyAvailable
SizeBytes = $sizeBytes
SizeGB = $sizeGB
FileCount = $fileCount
FolderCount = $folderCount
SizeError = $sizeError
})
}

return $rows
}

function Get-SharePermissions {
param([object[]]$Shares)

$rows = New-Object System.Collections.Generic.List[object]

foreach ($share in $Shares) {
try {
$perms = Get-SmbShareAccess -Name $share.ShareName -ErrorAction Stop

foreach ($perm in $perms) {
$rows.Add([pscustomobject]@{
Server = $share.Server
ShareName = $share.ShareName
AccountName = [string]$perm.AccountName
AccessControlType = [string]$perm.AccessControlType
AccessRight = [string]$perm.AccessRight
Status = "Success"
Error = $null
})
}
}
catch {
Write-Log "Could not read share permissions for $($share.ShareName): $($_.Exception.Message)" "WARN"

$rows.Add([pscustomobject]@{
Server = $share.Server
ShareName = $share.ShareName
AccountName = $null
AccessControlType = $null
AccessRight = $null
Status = "Failed"
Error = $_.Exception.Message
})
}
}

return $rows
}

function Get-NtfsAclRows {
param(
[object[]]$Shares,
[int]$Depth
)

$excludeFolderNames = @(
'System Volume Information',
'$RECYCLE.BIN',
'Recovery',
'RECYCLER'
)

$rows = New-Object System.Collections.Generic.List[object]

foreach ($share in $Shares) {
$shareDepth = $Depth
$configuredDepth = $null
$depthSource = "CommandLine"

if ($null -ne $share.PSObject.Properties["EffectiveAclDepth"]) {
$shareDepthValue = $share.PSObject.Properties["EffectiveAclDepth"].Value
if ($null -ne $shareDepthValue) {
$shareDepth = [int]$shareDepthValue
}
}

if ($null -ne $share.PSObject.Properties["ConfiguredScanDepth"]) {
$configuredDepth = $share.PSObject.Properties["ConfiguredScanDepth"].Value
}

if ($null -ne $share.PSObject.Properties["ScanDepthSource"]) {
$depthSourceValue = $share.PSObject.Properties["ScanDepthSource"].Value
if (-not [string]::IsNullOrWhiteSpace([string]$depthSourceValue)) {
$depthSource = [string]$depthSourceValue
}
}

Write-Log "Scanning NTFS ACLs for $($share.ShareName) at $($share.SharePath) to ACL depth $shareDepth, configured level $configuredDepth, source $depthSource"

if (-not (Test-Path -LiteralPath $share.SharePath)) {
$rows.Add([pscustomobject]@{
Server = $share.Server
ShareName = $share.ShareName
SharePath = $share.SharePath
ItemPath = $share.SharePath
Depth = 0
ScanDepth = $configuredDepth
EffectiveAclDepth = $shareDepth
Owner = $null
InheritanceProtected = $null
IdentityReference = $null
AccessControlType = $null
FileSystemRights = $null
IsInherited = $null
InheritanceFlags = $null
PropagationFlags = $null
RiskFlags = "PathNotFound"
SuggestedFix = Get-AclRemediationAdvice -RiskFlags "PathNotFound" -ScanStatus "Failed" -Error "Path not found or inaccessible" -IdentityReference $null -AccessControlType $null -FileSystemRights $null
ScanStatus = "Failed"
Error = "Path not found or inaccessible"
})
continue
}

$items = New-Object System.Collections.Generic.List[object]

try {
$rootItem = Get-Item -LiteralPath $share.SharePath -Force -ErrorAction Stop
$items.Add($rootItem)

if ($shareDepth -gt 0) {
$dirs = Get-ChildItem -LiteralPath $share.SharePath -Force -Directory -Recurse -ErrorAction SilentlyContinue |
Where-Object {
(Get-Depth -Root $share.SharePath -Current $_.FullName) -le $shareDepth -and
($excludeFolderNames -notcontains $_.Name)
}

foreach ($dir in $dirs) {
$items.Add($dir)
}
}
}
catch {
$rows.Add([pscustomobject]@{
Server = $share.Server
ShareName = $share.ShareName
SharePath = $share.SharePath
ItemPath = $share.SharePath
Depth = 0
ScanDepth = $configuredDepth
EffectiveAclDepth = $shareDepth
Owner = $null
InheritanceProtected = $null
IdentityReference = $null
AccessControlType = $null
FileSystemRights = $null
IsInherited = $null
InheritanceFlags = $null
PropagationFlags = $null
RiskFlags = "EnumerationFailed"
SuggestedFix = Get-AclRemediationAdvice -RiskFlags "EnumerationFailed" -ScanStatus "Failed" -Error $_.Exception.Message -IdentityReference $null -AccessControlType $null -FileSystemRights $null
ScanStatus = "Failed"
Error = $_.Exception.Message
})
continue
}

foreach ($item in $items) {
try {
$acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
$itemDepth = Get-Depth -Root $share.SharePath -Current $item.FullName

foreach ($ace in $acl.Access) {
$riskFlags = Get-AceRiskFlags -Acl $acl -Ace $ace
$rows.Add([pscustomobject]@{
Server = $share.Server
ShareName = $share.ShareName
SharePath = $share.SharePath
ItemPath = $item.FullName
Depth = $itemDepth
ScanDepth = $configuredDepth
EffectiveAclDepth = $shareDepth
Owner = [string]$acl.Owner
InheritanceProtected = [string]$acl.AreAccessRulesProtected
IdentityReference = [string]$ace.IdentityReference.Value
AccessControlType = [string]$ace.AccessControlType
FileSystemRights = [string]$ace.FileSystemRights
IsInherited = [string]$ace.IsInherited
InheritanceFlags = [string]$ace.InheritanceFlags
PropagationFlags = [string]$ace.PropagationFlags
RiskFlags = $riskFlags
SuggestedFix = Get-AclRemediationAdvice -RiskFlags $riskFlags -ScanStatus "Success" -Error $null -IdentityReference ([string]$ace.IdentityReference.Value) -AccessControlType ([string]$ace.AccessControlType) -FileSystemRights ([string]$ace.FileSystemRights)
ScanStatus = "Success"
Error = $null
})
}
}
catch {
$rows.Add([pscustomobject]@{
Server = $share.Server
ShareName = $share.ShareName
SharePath = $share.SharePath
ItemPath = $item.FullName
Depth = Get-Depth -Root $share.SharePath -Current $item.FullName
ScanDepth = $configuredDepth
EffectiveAclDepth = $shareDepth
Owner = $null
InheritanceProtected = $null
IdentityReference = $null
AccessControlType = $null
FileSystemRights = $null
IsInherited = $null
InheritanceFlags = $null
PropagationFlags = $null
RiskFlags = "AclReadDenied"
SuggestedFix = Get-AclRemediationAdvice -RiskFlags "AclReadDenied" -ScanStatus "Failed" -Error $_.Exception.Message -IdentityReference $null -AccessControlType $null -FileSystemRights $null
ScanStatus = "Failed"
Error = $_.Exception.Message
})
}
}
}

return $rows
}

function Get-RiskAssessment {
param(
[object[]]$Shares,
[object[]]$SharePermissions,
[object[]]$NtfsAcls
)

$rows = New-Object System.Collections.Generic.List[object]

foreach ($share in $Shares) {
$score = 0
$reasons = New-Object System.Collections.Generic.List[string]

$sp = @($SharePermissions | Where-Object { $_.ShareName -eq $share.ShareName })
$acl = @($NtfsAcls | Where-Object { $_.ShareName -eq $share.ShareName })

if ($sp | Where-Object { $_.AccountName -match "Everyone|Authenticated Users|BUILTIN\\Users" }) {
$score += 20
$reasons.Add("Broad share permission")
}

if ($acl | Where-Object { $_.RiskFlags -match "OrphanedSID" }) {
$score += 20
$reasons.Add("Orphaned SID")
}

if ($acl | Where-Object { $_.RiskFlags -match "BrokenInheritance" }) {
$score += 15
$reasons.Add("Broken inheritance")
}

if ($acl | Where-Object { $_.RiskFlags -match "PossibleDirectUserOrNonStandardGroup" }) {
$score += 15
$reasons.Add("Possible direct user or non-standard group")
}

if ($acl | Where-Object { $_.RiskFlags -match "DenyACE" }) {
$score += 10
$reasons.Add("Deny ACE")
}

if ($acl | Where-Object { $_.RiskFlags -match "FullControlACE" }) {
$score += 10
$reasons.Add("Full Control ACE")
}

if ($acl | Where-Object { $_.ScanStatus -eq "Failed" }) {
$score += 10
$reasons.Add("ACL scan failures")
}

$level = "Low"
if ($score -ge 70) { $level = "Critical" }
elseif ($score -ge 45) { $level = "High" }
elseif ($score -ge 20) { $level = "Medium" }

$rows.Add([pscustomobject]@{
Server = $share.Server
ShareName = $share.ShareName
SharePath = $share.SharePath
UNCPath = $share.UNCPath
RiskScore = $score
RiskLevel = $level
Reasons = ($reasons -join "; ")
})
}

return $rows
}

function Get-RobocopyPlan {
param(
[object[]]$Shares,
[string]$Target,
[int]$Threads
)

$rows = New-Object System.Collections.Generic.List[object]

foreach ($share in $Shares) {
$targetUnc = "\\$Target\$($share.ShareName)"
$safeShare = ($share.ShareName -replace '[\\/:*?"<>| ]','_')
$log = "C:\Temp\RobocopyLogs\robocopy_{0}_{1}.log" -f $share.Server, $safeShare

$cmd = 'robocopy "{0}" "{1}" /MIR /COPY:DATSOU /DCOPY:DAT /MT:{2} /R:2 /W:2 /ZB /FFT /XJ /TEE /NP /LOG+:"{3}"' -f $share.UNCPath, $targetUnc, $Threads, $log

$rows.Add([pscustomobject]@{
SourceServer = $share.Server
ShareName = $share.ShareName
SourceUNC = $share.UNCPath
TargetUNC = $targetUnc
LogPath = $log
RobocopyCommand = $cmd
})
}

return $rows
}

function Get-SafeFileNamePart {
param([string]$Value)

if ([string]::IsNullOrWhiteSpace($Value)) { return "Unknown" }
return ($Value -replace '[\\/:*?"<>| ]','_')
}

function Get-AccessDiagnosticErrorSignature {
param(
[string]$Error,
[string]$RiskFlags
)

$text = ([string]$Error).Trim()
if ([string]::IsNullOrWhiteSpace($text)) {
if (-not [string]::IsNullOrWhiteSpace($RiskFlags)) { return [string]$RiskFlags }
return "Unknown"
}

if ($text -match 'Access is denied|UnauthorizedAccess|permission') { return "AccessDenied" }
if ($text -match 'path.*too long|too long') { return "PathTooLong" }
if ($text -match 'could not find|cannot find|not found') { return "PathNotFound" }
if ($text -match 'being used by another process|lock') { return "LockedOrInUse" }
if ($text -match 'network path|network name|semaphore|specified server') { return "NetworkOrSmb" }

$clean = $text -replace '\s+', ' '
if ($clean.Length -gt 120) { return $clean.Substring(0, 120) }
return $clean
}

function Get-ChildFileSamples {
param(
[string]$Path,
[int]$Limit
)

if ($Limit -le 0 -or [string]::IsNullOrWhiteSpace($Path)) { return @() }

$samples = New-Object System.Collections.Generic.List[object]
$seen = @{}

try {
$directFiles = @(Get-ChildItem -LiteralPath $Path -Force -File -ErrorAction Stop | Select-Object -First $Limit)
foreach ($file in $directFiles) {
if ($null -ne $file -and -not $seen.ContainsKey([string]$file.FullName)) {
$seen[[string]$file.FullName] = $true
$samples.Add($file)
}
}
}
catch {
}

if ($samples.Count -lt $Limit) {
try {
$recursiveFiles = @(Get-ChildItem -LiteralPath $Path -Force -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First $Limit)
foreach ($file in $recursiveFiles) {
if ($samples.Count -ge $Limit) { break }
if ($null -ne $file -and -not $seen.ContainsKey([string]$file.FullName)) {
$seen[[string]$file.FullName] = $true
$samples.Add($file)
}
}
}
catch {
}
}

return @($samples.ToArray())
}

function Test-DiagnosticFileAccess {
param([string]$Path)

$readSucceeded = $false
$readError = $null
$aclSucceeded = $false
$aclError = $null
$stream = $null

try {
$stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
$readSucceeded = $true
}
catch {
$readError = $_.Exception.Message
}
finally {
if ($null -ne $stream) { $stream.Dispose() }
}

try {
Get-Acl -LiteralPath $Path -ErrorAction Stop | Out-Null
$aclSucceeded = $true
}
catch {
$aclError = $_.Exception.Message
}

return [pscustomobject]@{
CanReadFile = $readSucceeded
ReadError = $readError
CanReadFileAcl = $aclSucceeded
AclError = $aclError
}
}

function Invoke-RobocopyDiagnosticRun {
param(
[string]$SourceDirectory,
[string]$FileName,
[string]$TestRoot,
[string]$LogRoot,
[string]$TestName,
[string]$CopyFlags,
[long]$SourceBytes
)

$testDestination = Join-Path $TestRoot $TestName
$logFile = Join-Path $LogRoot "$TestName.log"
New-Item -Path $testDestination -ItemType Directory -Force | Out-Null

$arguments = @(
$SourceDirectory,
$testDestination,
$FileName,
"/COPY:$CopyFlags",
"/DCOPY:DAT",
"/R:0",
"/W:0",
"/FFT",
"/NP",
"/LOG:$logFile"
)

& robocopy.exe @arguments | Out-Null
$exitCode = $LASTEXITCODE
$destinationFile = Join-Path $testDestination $FileName
$fileExists = Test-Path -LiteralPath $destinationFile -PathType Leaf -ErrorAction SilentlyContinue
$destinationBytes = $null
if ($fileExists) {
try {
$destinationBytes = (Get-Item -LiteralPath $destinationFile -ErrorAction Stop).Length
}
catch {
$destinationBytes = $null
}
}

return [pscustomobject]@{
Test = $TestName
CopyFlags = $CopyFlags
ExitCode = $exitCode
RobocopySuccess = ($exitCode -lt 8)
DestinationExists = $fileExists
SourceBytes = $SourceBytes
DestinationBytes = $destinationBytes
SizeMatches = ($fileExists -and $null -ne $destinationBytes -and $destinationBytes -eq $SourceBytes)
DestinationFile = $destinationFile
LogFile = $logFile
}
}

function Get-RobocopyDiagnosticDiagnosis {
param([object[]]$Results)

$datResult = @($Results | Where-Object { $_.Test -eq "01-DAT" } | Select-Object -First 1)
$datsResult = @($Results | Where-Object { $_.Test -eq "02-DATS" } | Select-Object -First 1)
$datsoResult = @($Results | Where-Object { $_.Test -eq "03-DATSO" } | Select-Object -First 1)

if ($datResult.Count -eq 0 -or $datsResult.Count -eq 0 -or $datsoResult.Count -eq 0) {
return [pscustomobject]@{
Category = "Incomplete"
Diagnosis = "The isolated robocopy diagnostic did not complete all test modes."
RecommendedFix = "Review the diagnostic logs and rerun the probe after confirming the source file and test destination are reachable."
RecommendedCopyMode = ""
}
}

if (-not [bool]$datResult[0].RobocopySuccess) {
return [pscustomobject]@{
Category = "DATFailed"
Diagnosis = "The basic data, attributes, and timestamp copy failed."
RecommendedFix = "This is not limited to NTFS permissions. Check source-file access, destination write access, SMB connectivity, file locks, path length, invalid names, and storage availability before changing ACLs."
RecommendedCopyMode = ""
}
}

if (-not [bool]$datsResult[0].RobocopySuccess) {
return [pscustomobject]@{
Category = "DATSFailed"
Diagnosis = "DAT succeeded, but copying the DACL failed."
RecommendedFix = "Data can be copied, but applying NTFS permissions fails. Look for malformed ACLs, unresolved or obsolete SIDs, local server accounts in ACLs, missing rights to write security descriptors, or destination NTFS security-style/SID-resolution issues."
RecommendedCopyMode = ""
}
}

if (-not [bool]$datsoResult[0].RobocopySuccess) {
return [pscustomobject]@{
Category = "DATSOFailed"
Diagnosis = "DAT and DATS succeeded, but copying ownership failed."
RecommendedFix = "The ACL is copyable, but owner preservation is the blocker. Owners may be unresolved SIDs, local accounts from the old file server, or identities the migration account cannot assign. Use /COPY:DATS for the migration pass, then repair owners deliberately where required."
RecommendedCopyMode = "/COPY:DATS"
}
}

return [pscustomobject]@{
Category = "Passed"
Diagnosis = "All isolated robocopy tests completed with non-failure exit codes."
RecommendedFix = "The sampled file did not reproduce the original failure. Check whether the failure is intermittent, path-specific, only appears under a larger multithreaded job, or occurs on a different child item."
RecommendedCopyMode = "/COPY:DATSOU"
}
}

function Invoke-RobocopySecurityDiagnostic {
param(
[string]$SourceFile,
[string]$DestinationRoot,
[string]$ServerName,
[string]$ShareName
)

$emptyResult = [ordered]@{
RobocopyStatus = "Skipped"
RobocopyDiagnosis = ""
RobocopyRecommendedFix = ""
RecommendedCopyMode = ""
RobocopyTestRoot = ""
RobocopyReportPath = ""
RobocopyLogRoot = ""
DatExitCode = ""
DatsExitCode = ""
DatsoExitCode = ""
DatSuccess = ""
DatsSuccess = ""
DatsoSuccess = ""
}

if ([string]::IsNullOrWhiteSpace($DestinationRoot)) {
$emptyResult["RobocopyDiagnosis"] = "Robocopy probe not run because -RobocopyDiagnosticDestinationRoot was not supplied."
return [pscustomobject]$emptyResult
}

if ([string]::IsNullOrWhiteSpace($SourceFile) -or -not (Test-Path -LiteralPath $SourceFile -PathType Leaf -ErrorAction SilentlyContinue)) {
$emptyResult["RobocopyStatus"] = "NoSampleFile"
$emptyResult["RobocopyDiagnosis"] = "No accessible sample file was found for this failure scope."
return [pscustomobject]$emptyResult
}

if ($null -eq (Get-Command robocopy.exe -ErrorAction SilentlyContinue)) {
$emptyResult["RobocopyStatus"] = "RobocopyMissing"
$emptyResult["RobocopyDiagnosis"] = "robocopy.exe was not found on this system."
return [pscustomobject]$emptyResult
}

try {
if (-not (Test-Path -LiteralPath $DestinationRoot -ErrorAction SilentlyContinue)) {
New-Item -Path $DestinationRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
}

$sourceItem = Get-Item -LiteralPath $SourceFile -ErrorAction Stop
$sourceDirectory = $sourceItem.DirectoryName
$fileName = $sourceItem.Name
$safeServer = Get-SafeFileNamePart -Value $ServerName
$safeShare = Get-SafeFileNamePart -Value $ShareName
$timeStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$testRoot = Join-Path $DestinationRoot ("SecurityTest-{0}-{1}-{2}" -f $safeServer, $safeShare, $timeStamp)
$logRoot = Join-Path $testRoot "Logs"
New-Item -Path $testRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
New-Item -Path $logRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null

$aclReadSucceeded = $false
$sourceAcl = $null
$aclError = $null
try {
$sourceAcl = Get-Acl -LiteralPath $SourceFile -ErrorAction Stop
$aclReadSucceeded = $true
}
catch {
$aclError = $_.Exception.Message
}

$results = @()
$results += Invoke-RobocopyDiagnosticRun -SourceDirectory $sourceDirectory -FileName $fileName -TestRoot $testRoot -LogRoot $logRoot -TestName "01-DAT" -CopyFlags "DAT" -SourceBytes $sourceItem.Length
$results += Invoke-RobocopyDiagnosticRun -SourceDirectory $sourceDirectory -FileName $fileName -TestRoot $testRoot -LogRoot $logRoot -TestName "02-DATS" -CopyFlags "DATS" -SourceBytes $sourceItem.Length
$results += Invoke-RobocopyDiagnosticRun -SourceDirectory $sourceDirectory -FileName $fileName -TestRoot $testRoot -LogRoot $logRoot -TestName "03-DATSO" -CopyFlags "DATSO" -SourceBytes $sourceItem.Length

$diagnosis = Get-RobocopyDiagnosticDiagnosis -Results $results
$resultCsv = Join-Path $testRoot "Robocopy-Test-Results.csv"
$reportFile = Join-Path $testRoot "Robocopy-Diagnosis.txt"
$results | Export-Csv -Path $resultCsv -NoTypeInformation -Encoding UTF8

$sourceOwner = ""
$sourceGroup = ""
$protectedAcl = ""
if ($null -ne $sourceAcl) {
$sourceOwner = [string]$sourceAcl.Owner
$sourceGroup = [string]$sourceAcl.Group
$protectedAcl = [string]$sourceAcl.AreAccessRulesProtected
}

@"
Robocopy security diagnostic
Generated: $(Get-Date)

Source:
$SourceFile

Destination test root:
$testRoot

Source ACL readable:
$aclReadSucceeded

Source ACL error:
$aclError

Source owner:
$sourceOwner

Source group:
$sourceGroup

Protected ACL:
$protectedAcl

Results:
$($results | Format-Table Test, CopyFlags, ExitCode, RobocopySuccess, DestinationExists, SizeMatches -AutoSize | Out-String)

Diagnosis:
$($diagnosis.Diagnosis)

Recommended fix:
$($diagnosis.RecommendedFix)
"@ | Set-Content -Path $reportFile -Encoding UTF8

$dat = @($results | Where-Object { $_.Test -eq "01-DAT" } | Select-Object -First 1)
$dats = @($results | Where-Object { $_.Test -eq "02-DATS" } | Select-Object -First 1)
$datso = @($results | Where-Object { $_.Test -eq "03-DATSO" } | Select-Object -First 1)

$output = [ordered]@{}
foreach ($entry in $emptyResult.GetEnumerator()) {
$output[$entry.Key] = $entry.Value
}
$output["RobocopyStatus"] = "Completed"
$output["RobocopyDiagnosis"] = [string]$diagnosis.Diagnosis
$output["RobocopyRecommendedFix"] = [string]$diagnosis.RecommendedFix
$output["RecommendedCopyMode"] = [string]$diagnosis.RecommendedCopyMode
$output["RobocopyTestRoot"] = $testRoot
$output["RobocopyReportPath"] = $reportFile
$output["RobocopyLogRoot"] = $logRoot
$output["DatExitCode"] = if ($dat.Count -gt 0) { [string]$dat[0].ExitCode } else { "" }
$output["DatsExitCode"] = if ($dats.Count -gt 0) { [string]$dats[0].ExitCode } else { "" }
$output["DatsoExitCode"] = if ($datso.Count -gt 0) { [string]$datso[0].ExitCode } else { "" }
$output["DatSuccess"] = if ($dat.Count -gt 0) { [string]$dat[0].RobocopySuccess } else { "" }
$output["DatsSuccess"] = if ($dats.Count -gt 0) { [string]$dats[0].RobocopySuccess } else { "" }
$output["DatsoSuccess"] = if ($datso.Count -gt 0) { [string]$datso[0].RobocopySuccess } else { "" }
return [pscustomobject]$output
}
catch {
$emptyResult["RobocopyStatus"] = "Failed"
$emptyResult["RobocopyDiagnosis"] = $_.Exception.Message
$emptyResult["RobocopyRecommendedFix"] = "Confirm the diagnostic destination is writable and that the sampled source file is reachable, then rerun the audit."
return [pscustomobject]$emptyResult
}
}

function Get-AccessDiagnosticAdvice {
param(
[string]$RiskFlags,
[string]$ErrorSignature,
[string]$PathType,
[bool]$AclReadable,
[bool]$CanEnumerate,
[int]$SampleFileCount,
[int]$SampleFileErrors,
[int]$UnresolvedAceCount,
[int]$LocalIdentityCount,
[string]$Owner,
[object]$RobocopyProbe
)

$causes = New-Object System.Collections.Generic.List[string]
$fixes = New-Object System.Collections.Generic.List[string]

if ($RiskFlags -match "PathNotFound" -or $ErrorSignature -eq "PathNotFound") {
$causes.Add("The path was not found or was invisible to the audit account.")
$fixes.Add("Verify the share path, DFS target, mount point, and account visibility before changing permissions.")
}

if ($RiskFlags -match "EnumerationFailed") {
$causes.Add("The folder could not be enumerated.")
$fixes.Add("Check List Folder/Read Data and Traverse Folder rights on this scope and its parent. Fix the first blocked folder rather than changing every child.")
}

if ($RiskFlags -match "AclReadDenied" -or $ErrorSignature -eq "AccessDenied" -or -not $AclReadable) {
$causes.Add("The object exists, but the audit account could not read its security descriptor.")
$fixes.Add("Do not reset ACLs. Back up permissions first with icacls /save, rerun elevated or as local admin/SYSTEM, then take ownership only on this scope and add a temporary admin ACE if needed.")
}

if ($PathType -eq "Folder" -and -not $CanEnumerate) {
$causes.Add("The folder itself could not be listed.")
$fixes.Add("Repair access at this folder or the nearest parent so one inherited fix can unblock the children.")
}

if ($SampleFileCount -gt 0 -and $SampleFileErrors -eq $SampleFileCount) {
$causes.Add("All sampled child files failed read or ACL checks.")
$fixes.Add("Treat this as a folder-level inheritance or ownership problem. Fix the folder or first bad child, then rerun instead of chasing every file error.")
}

if ($UnresolvedAceCount -gt 0) {
$causes.Add("Visible ACL entries contain unresolved SIDs.")
$fixes.Add("Map unresolved SIDs to migrated identities where possible. Remove only obsolete ACEs after the ACL backup.")
}

if ($LocalIdentityCount -gt 0) {
$causes.Add("Visible ACL entries contain local machine accounts.")
$fixes.Add("Replace local-server principals with approved domain groups before migration to storage that cannot resolve the old local accounts.")
}

if ($Owner -match '^S-\d-') {
$causes.Add("The owner is an unresolved SID.")
$fixes.Add("Set ownership only on the affected scope to an approved admin or data-owner group after backing up ACLs; do not replace the existing DACL.")
}

$computerName = [string]$env:COMPUTERNAME
if (-not [string]::IsNullOrWhiteSpace($computerName) -and $Owner -like "$computerName\*") {
$causes.Add("The owner is a local account from this file server.")
$fixes.Add("Move ownership to a domain group or service account that will exist on the destination, then rerun the diagnostic.")
}

if ($null -ne $RobocopyProbe -and [string]$RobocopyProbe.RobocopyStatus -eq "Completed") {
$causes.Add([string]$RobocopyProbe.RobocopyDiagnosis)
$fixes.Add([string]$RobocopyProbe.RobocopyRecommendedFix)
}
elseif ($null -ne $RobocopyProbe -and -not [string]::IsNullOrWhiteSpace([string]$RobocopyProbe.RobocopyDiagnosis)) {
$causes.Add([string]$RobocopyProbe.RobocopyDiagnosis)
}

if ($causes.Count -eq 0) {
$causes.Add("The failure needs manual review; the sampled checks did not isolate one clear root cause.")
}

if ($fixes.Count -eq 0) {
$fixes.Add("Back up ACLs first, make the smallest reversible change at the highest affected folder, then rerun the audit.")
}

return [pscustomobject]@{
LikelyCause = (($causes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) -join " ")
RecommendedFix = (($fixes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) -join " ")
}
}

function Get-AccessDiagnosticRows {
param(
[object[]]$NtfsAcls,
[string]$DestinationRoot,
[int]$MaxGroups,
[int]$MaxFileSamplesPerFolder
)

$failedRows = @($NtfsAcls | Where-Object { [string]$_.ScanStatus -eq "Failed" })
if ($failedRows.Count -eq 0) { return @() }

$groups = @{}
$groupOrder = New-Object System.Collections.Generic.List[string]

foreach ($row in $failedRows) {
$scopePath = [string]$row.ItemPath
if ([string]::IsNullOrWhiteSpace($scopePath)) { $scopePath = [string]$row.SharePath }
$riskFlags = [string]$row.RiskFlags
$errorSignature = Get-AccessDiagnosticErrorSignature -Error ([string]$row.Error) -RiskFlags $riskFlags
$key = "{0}|{1}|{2}|{3}|{4}" -f ([string]$row.Server), ([string]$row.ShareName), $scopePath.ToLowerInvariant(), $riskFlags, $errorSignature

if (-not $groups.ContainsKey($key)) {
$groups[$key] = [ordered]@{
Row = $row
ScopePath = $scopePath
RiskFlags = $riskFlags
ErrorSignature = $errorSignature
FailureCount = 0
}
$groupOrder.Add($key)
}

$groups[$key]["FailureCount"] = [int]$groups[$key]["FailureCount"] + 1
}

$rows = New-Object System.Collections.Generic.List[object]
$processed = 0

foreach ($key in $groupOrder) {
if ($processed -ge $MaxGroups) { break }

$group = $groups[$key]
$sourceRow = $group["Row"]
$scopePath = [string]$group["ScopePath"]
$riskFlags = [string]$group["RiskFlags"]
$errorSignature = [string]$group["ErrorSignature"]
$processed++

Write-Log "Running access diagnostic for $($sourceRow.ShareName): $scopePath"

$pathExists = Test-Path -LiteralPath $scopePath -ErrorAction SilentlyContinue
$pathType = "NotAccessibleOrMissing"
if (Test-Path -LiteralPath $scopePath -PathType Container -ErrorAction SilentlyContinue) {
$pathType = "Folder"
}
elseif (Test-Path -LiteralPath $scopePath -PathType Leaf -ErrorAction SilentlyContinue) {
$pathType = "File"
}
elseif ($pathExists) {
$pathType = "Other"
}

$owner = ""
$groupName = ""
$inheritanceProtected = ""
$aclReadable = $false
$aclError = ""
$unresolvedAceCount = 0
$localIdentityCount = 0

try {
$acl = Get-Acl -LiteralPath $scopePath -ErrorAction Stop
$aclReadable = $true
$owner = [string]$acl.Owner
$groupName = [string]$acl.Group
$inheritanceProtected = [string]$acl.AreAccessRulesProtected
$unresolvedAceCount = @($acl.Access | Where-Object { [string]$_.IdentityReference.Value -match '^S-\d-' }).Count
$computerName = [string]$env:COMPUTERNAME
if (-not [string]::IsNullOrWhiteSpace($computerName)) {
$localIdentityCount = @($acl.Access | Where-Object { [string]$_.IdentityReference.Value -like "$computerName\*" }).Count
}
}
catch {
$aclError = $_.Exception.Message
}

$canEnumerate = $false
$directFileCount = ""
$directFolderCount = ""
$sampleFiles = @()
$sampleFileCount = 0
$sampleFileErrors = 0
$sampleFileErrorSummary = ""

if ($pathType -eq "Folder") {
try {
$directChildren = @(Get-ChildItem -LiteralPath $scopePath -Force -ErrorAction Stop)
$canEnumerate = $true
$directFileCount = @($directChildren | Where-Object { -not $_.PSIsContainer }).Count
$directFolderCount = @($directChildren | Where-Object { $_.PSIsContainer }).Count
}
catch {
$sampleFileErrorSummary = $_.Exception.Message
}

$sampleFiles = @(Get-ChildFileSamples -Path $scopePath -Limit $MaxFileSamplesPerFolder)
}
elseif ($pathType -eq "File") {
try {
$sampleFiles = @(Get-Item -LiteralPath $scopePath -ErrorAction Stop)
}
catch {
$sampleFiles = @()
}
}

$fileErrors = New-Object System.Collections.Generic.List[string]
foreach ($file in @($sampleFiles)) {
$sampleFileCount++
$fileAccess = Test-DiagnosticFileAccess -Path ([string]$file.FullName)
if (-not $fileAccess.CanReadFile -or -not $fileAccess.CanReadFileAcl) {
$sampleFileErrors++
if (-not [string]::IsNullOrWhiteSpace([string]$fileAccess.ReadError)) { $fileErrors.Add([string]$fileAccess.ReadError) }
if (-not [string]::IsNullOrWhiteSpace([string]$fileAccess.AclError)) { $fileErrors.Add([string]$fileAccess.AclError) }
}
}

if ($fileErrors.Count -gt 0) {
$sampleFileErrorSummary = (($fileErrors.ToArray() | Sort-Object -Unique) -join " ")
}

$sampleFile = ""
if ($sampleFiles.Count -gt 0) {
$sampleFile = [string]$sampleFiles[0].FullName
}

$robocopyProbe = Invoke-RobocopySecurityDiagnostic -SourceFile $sampleFile -DestinationRoot $DestinationRoot -ServerName ([string]$sourceRow.Server) -ShareName ([string]$sourceRow.ShareName)
$advice = Get-AccessDiagnosticAdvice -RiskFlags $riskFlags -ErrorSignature $errorSignature -PathType $pathType -AclReadable $aclReadable -CanEnumerate $canEnumerate -SampleFileCount $sampleFileCount -SampleFileErrors $sampleFileErrors -UnresolvedAceCount $unresolvedAceCount -LocalIdentityCount $localIdentityCount -Owner $owner -RobocopyProbe $robocopyProbe

$rows.Add([pscustomobject]@{
Server = [string]$sourceRow.Server
ShareName = [string]$sourceRow.ShareName
SharePath = [string]$sourceRow.SharePath
ScopePath = $scopePath
Depth = $sourceRow.Depth
ScanDepth = $sourceRow.ScanDepth
EffectiveAclDepth = $sourceRow.EffectiveAclDepth
FailureCount = [int]$group["FailureCount"]
RiskFlags = $riskFlags
ErrorSignature = $errorSignature
OriginalError = [string]$sourceRow.Error
PathExists = [string]$pathExists
PathType = $pathType
CanReadAcl = [string]$aclReadable
AclError = $aclError
CanEnumerate = [string]$canEnumerate
Owner = $owner
Group = $groupName
InheritanceProtected = $inheritanceProtected
UnresolvedAceCount = $unresolvedAceCount
LocalIdentityCount = $localIdentityCount
DirectFileCount = $directFileCount
DirectFolderCount = $directFolderCount
SampleFile = $sampleFile
SampleFileCount = $sampleFileCount
SampleFileErrors = $sampleFileErrors
SampleFileErrorSummary = $sampleFileErrorSummary
RobocopyStatus = [string]$robocopyProbe.RobocopyStatus
RobocopyDiagnosis = [string]$robocopyProbe.RobocopyDiagnosis
RecommendedCopyMode = [string]$robocopyProbe.RecommendedCopyMode
DatExitCode = [string]$robocopyProbe.DatExitCode
DatsExitCode = [string]$robocopyProbe.DatsExitCode
DatsoExitCode = [string]$robocopyProbe.DatsoExitCode
RobocopyTestRoot = [string]$robocopyProbe.RobocopyTestRoot
RobocopyReportPath = [string]$robocopyProbe.RobocopyReportPath
RobocopyLogRoot = [string]$robocopyProbe.RobocopyLogRoot
LikelyCause = [string]$advice.LikelyCause
RecommendedFix = [string]$advice.RecommendedFix
})
}

$remaining = $groupOrder.Count - $processed
if ($remaining -gt 0) {
$rows.Add([pscustomobject]@{
Server = ""
ShareName = ""
SharePath = ""
ScopePath = "Diagnostic group cap reached"
Depth = ""
ScanDepth = ""
EffectiveAclDepth = ""
FailureCount = $remaining
RiskFlags = "DiagnosticLimit"
ErrorSignature = "MaxAccessDiagnosticGroups"
OriginalError = ""
PathExists = ""
PathType = ""
CanReadAcl = ""
AclError = ""
CanEnumerate = ""
Owner = ""
Group = ""
InheritanceProtected = ""
UnresolvedAceCount = ""
LocalIdentityCount = ""
DirectFileCount = ""
DirectFolderCount = ""
SampleFile = ""
SampleFileCount = ""
SampleFileErrors = ""
SampleFileErrorSummary = ""
RobocopyStatus = "Skipped"
RobocopyDiagnosis = "Increase -MaxAccessDiagnosticGroups to inspect the remaining failure groups."
RecommendedCopyMode = ""
DatExitCode = ""
DatsExitCode = ""
DatsoExitCode = ""
RobocopyTestRoot = ""
RobocopyReportPath = ""
RobocopyLogRoot = ""
LikelyCause = "More unique access failure groups were found than the configured diagnostic cap."
RecommendedFix = "Fix the listed higher-level scopes first, then rerun. If more detail is needed, increase -MaxAccessDiagnosticGroups."
})
}

return @($rows.ToArray())
}

function Convert-ForJson {
param([object[]]$Rows)

if ($null -eq $Rows) { return @() }
return @($Rows)
}

function Get-UserAccessRows {
param(
[object[]]$Shares,
[object[]]$SharePermissions,
[object[]]$NtfsAcls
)

$rows = New-Object System.Collections.Generic.List[object]
$shareLookup = @{}

foreach ($share in @($Shares)) {
if ($null -ne $share.ShareName) {
$shareLookup[[string]$share.ShareName] = $share
}
}

foreach ($perm in @($SharePermissions)) {
$principal = [string]$perm.AccountName
if ([string]::IsNullOrWhiteSpace($principal)) { continue }

$shareName = [string]$perm.ShareName
$sharePath = $null
$itemPath = $null

if (-not [string]::IsNullOrWhiteSpace($shareName) -and $shareLookup.ContainsKey($shareName)) {
$shareInfo = $shareLookup[$shareName]
$sharePath = [string]$shareInfo.SharePath
$itemPath = [string]$shareInfo.UNCPath
}

$riskFlags = ""
if ($principal -match "Everyone|Authenticated Users|BUILTIN\\Users") {
$riskFlags = "BroadPrincipal"
}

$rows.Add([pscustomobject]@{
Principal = $principal
AccessSource = "SharePermission"
Server = [string]$perm.Server
ShareName = $shareName
SharePath = $sharePath
ItemPath = $itemPath
AccessControlType = [string]$perm.AccessControlType
AccessRights = [string]$perm.AccessRight
IsInherited = $null
RiskFlags = $riskFlags
SuggestedFix = Get-AclRemediationAdvice -RiskFlags $riskFlags -ScanStatus ([string]$perm.Status) -Error $perm.Error -IdentityReference $principal -AccessControlType ([string]$perm.AccessControlType) -FileSystemRights ([string]$perm.AccessRight)
Status = [string]$perm.Status
Error = $perm.Error
})
}

foreach ($acl in @($NtfsAcls)) {
$principal = [string]$acl.IdentityReference
if ([string]::IsNullOrWhiteSpace($principal)) { continue }

$rows.Add([pscustomobject]@{
Principal = $principal
AccessSource = "NTFS"
Server = [string]$acl.Server
ShareName = [string]$acl.ShareName
SharePath = [string]$acl.SharePath
ItemPath = [string]$acl.ItemPath
AccessControlType = [string]$acl.AccessControlType
AccessRights = [string]$acl.FileSystemRights
IsInherited = [string]$acl.IsInherited
RiskFlags = [string]$acl.RiskFlags
SuggestedFix = [string]$acl.SuggestedFix
Status = [string]$acl.ScanStatus
Error = $acl.Error
})
}

return $rows
}

function New-DashboardHtml {
param(
[string]$HtmlPath
)

$html = @'
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>FileShareToolkit Portable Dashboard</title>
<style>
:root {
--bg:#0f172a; --panel:#111827; --card:#1f2937; --text:#e5e7eb; --muted:#9ca3af;
--border:#374151; --accent:#60a5fa; --bad:#ef4444; --warn:#f59e0b; --ok:#22c55e;
}
* { box-sizing:border-box; }
body { margin:0; font-family:Segoe UI,Arial,sans-serif; background:var(--bg); color:var(--text); }
header { padding:22px 30px; background:#020617; border-bottom:1px solid var(--border); position:sticky; top:0; z-index:5; }
h1 { margin:0 0 6px 0; font-size:26px; }
h2 { margin:26px 0 10px; }
main { padding:22px 30px; }
.muted { color:var(--muted); }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:20px; }
.card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:14px; }
.card .num { font-size:26px; font-weight:700; margin-top:4px; }
.bad { color:var(--bad); } .warn { color:var(--warn); } .ok { color:var(--ok); }
.section { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px; margin-top:16px; }
.controls { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:10px; }
input, select, button, textarea { padding:9px 11px; border-radius:8px; border:1px solid var(--border); background:#020617; color:var(--text); }
input { min-width:320px; }
textarea { min-height:88px; width:100%; resize:vertical; font-family:Consolas,monospace; }
button { cursor:pointer; }
button:hover { border-color:var(--accent); }
.header-actions { display:flex; gap:8px; flex-wrap:wrap; margin-top:12px; }
.action-link { display:inline-block; padding:9px 11px; border-radius:8px; border:1px solid var(--accent); background:#020617; color:#fff; }
.table-wrap { overflow:auto; max-height:520px; border:1px solid var(--border); border-radius:8px; }
table { border-collapse:collapse; width:100%; font-size:12px; }
th,td { border-bottom:1px solid var(--border); padding:7px 8px; white-space:nowrap; vertical-align:top; }
th { position:sticky; top:0; background:#020617; color:#fff; text-align:left; }
.filter-row th { top:33px; }
.sortbtn { width:100%; padding:0; border:0; background:transparent; color:#fff; text-align:left; font-weight:700; }
.column-filter { width:100%; min-width:120px; padding:6px 7px; font-size:11px; }
tr:hover { background:#1e293b; }
a { color:var(--accent); text-decoration:none; }
.tabs { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:14px; }
.tab { padding:10px 12px; background:#020617; border:1px solid var(--border); border-radius:8px; cursor:pointer; }
.tab.active { border-color:var(--accent); color:#fff; }
.hidden { display:none; }
.copybtn { font-size:11px; padding:5px 8px; }
.row-count { align-self:center; color:var(--muted); font-size:12px; }
.dropdown { position:relative; }
.dropdown-menu { position:absolute; z-index:20; top:43px; left:0; width:360px; max-width:calc(100vw - 70px); max-height:390px; overflow:auto; background:#020617; border:1px solid var(--border); border-radius:8px; padding:10px; box-shadow:0 18px 40px rgba(0,0,0,.35); }
.dropdown-actions { display:flex; gap:8px; margin-bottom:8px; }
.dropdown-menu input[type="text"] { width:100%; min-width:0; margin-bottom:8px; }
.check-row { display:flex; gap:8px; align-items:flex-start; padding:6px 4px; border-radius:6px; }
.check-row:hover { background:#111827; }
.check-row input { min-width:0; margin-top:2px; }
.form-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:12px; margin-bottom:14px; }
.field label { display:block; margin-bottom:5px; color:var(--muted); font-size:12px; }
.field input, .field select { width:100%; min-width:0; }
.note { border:1px solid var(--border); border-radius:8px; padding:10px 12px; color:var(--muted); background:#020617; margin-bottom:12px; }
.status-line { color:var(--muted); font-size:12px; align-self:center; }
.config-table select { min-width:95px; }
@media print {
body { background:#fff; color:#000; }
header { position:static; background:#fff; color:#000; border-bottom:1px solid #999; }
main { padding:12px; }
.tabs, .controls, .header-actions, .filter-row, .copybtn { display:none !important; }
.hidden { display:block !important; }
.section { background:#fff; color:#000; border:1px solid #999; page-break-inside:avoid; }
.card { background:#fff; color:#000; border:1px solid #999; }
.table-wrap { max-height:none; overflow:visible; border:0; }
table { font-size:9px; }
th { position:static; background:#eee; color:#000; }
td, th { color:#000; white-space:normal; }
}
</style>
</head>
<body>
<header>
<h1>FileShareToolkit Portable Dashboard</h1>
<div class="muted" id="subtitle">Loading data.json...</div>
<div class="header-actions hidden" id="centralActions">
<a class="action-link" id="centralGenerateLink" href="Generate-CentralDashboard.cmd">Regenerate central dashboard</a>
</div>
<div class="header-actions hidden" id="configHelperActions">
<a class="action-link" id="configHelperLink" href="Start-ConfigSaveServer.cmd">Start config save server</a>
</div>
<div class="header-actions">
<button type="button" onclick="exportCompleteCsv()">Export CSV</button>
<button type="button" onclick="exportExcelWorkbook()">Export XLS</button>
<button type="button" onclick="exportPdf()">Export PDF</button>
</div>
</header>
<main>
<div class="grid" id="cards"></div>

<div class="tabs">
<div class="tab active" onclick="showTab('risk')">Risk</div>
<div class="tab" onclick="showTab('shares')">Shares</div>
<div class="tab" onclick="showTab('acls')">Problem ACLs</div>
<div class="tab" onclick="showTab('diag')">Diagnostics</div>
<div class="tab" onclick="showTab('perms')">Share Permissions</div>
<div class="tab" onclick="showTab('users')">User Access</div>
<div class="tab" onclick="showTab('robo')">Robocopy</div>
<div class="tab" onclick="showTab('config')">Scan Config</div>
<div class="tab" onclick="showTab('files')">Files</div>
</div>

<section id="tab-risk" class="section">
<h2>Risk Assessment</h2>
<div class="controls">
<input id="riskSearch" placeholder="Search risks..." oninput="renderTable('risk')">
<button type="button" onclick="clearFilters('risk')">Clear filters</button>
<span class="row-count" id="riskCount"></span>
</div>
<div class="table-wrap"><table id="riskTable"></table></div>
</section>

<section id="tab-shares" class="section hidden">
<h2>Shares</h2>
<div class="controls">
<input id="shareSearch" placeholder="Search shares..." oninput="renderTable('shares')">
<button type="button" onclick="clearFilters('shares')">Clear filters</button>
<span class="row-count" id="sharesCount"></span>
</div>
<div class="table-wrap"><table id="shareTable"></table></div>
</section>

<section id="tab-acls" class="section hidden">
<h2>Problem ACL Entries</h2>
<div class="controls">
<input id="aclSearch" placeholder="Search ACLs..." oninput="renderTable('acls')">
<select id="aclLimit" onchange="renderTable('acls')">
<option value="500">500 rows</option>
<option value="1000" selected>1000 rows</option>
<option value="5000">5000 rows</option>
<option value="999999">All rows</option>
</select>
<button type="button" onclick="clearFilters('acls')">Clear filters</button>
<span class="row-count" id="aclsCount"></span>
</div>
<div class="table-wrap"><table id="aclTable"></table></div>
</section>

<section id="tab-diag" class="section hidden">
<h2>Access Diagnostics</h2>
<div class="controls">
<input id="diagSearch" placeholder="Search diagnostics..." oninput="renderTable('diag')">
<button type="button" onclick="clearFilters('diag')">Clear filters</button>
<span class="row-count" id="diagCount"></span>
</div>
<div class="table-wrap"><table id="diagTable"></table></div>
</section>

<section id="tab-perms" class="section hidden">
<h2>Share Permissions</h2>
<div class="controls">
<input id="permSearch" placeholder="Search share permissions..." oninput="renderTable('perms')">
<button type="button" onclick="clearFilters('perms')">Clear filters</button>
<span class="row-count" id="permsCount"></span>
</div>
<div class="table-wrap"><table id="permTable"></table></div>
</section>

<section id="tab-users" class="section hidden">
<h2>User Access</h2>
<div class="controls">
<input id="userAccessSearch" placeholder="Search user access..." oninput="renderTable('users')">
<div class="dropdown">
<button type="button" id="userFilterButton" onclick="toggleUserDropdown()">All users</button>
<div class="dropdown-menu hidden" id="userFilterMenu">
<input id="userOptionSearch" type="text" placeholder="Find user..." oninput="renderUserDropdown()">
<div class="dropdown-actions">
<button type="button" onclick="clearUserSelection()">Show all</button>
</div>
<div id="userFilterOptions"></div>
</div>
</div>
<button type="button" onclick="clearFilters('users')">Clear filters</button>
<span class="row-count" id="usersCount"></span>
</div>
<div class="table-wrap"><table id="userAccessTable"></table></div>
</section>

<section id="tab-robo" class="section hidden">
<h2>Robocopy Migration Plan</h2>
<div class="controls">
<input id="roboSearch" placeholder="Search robocopy commands..." oninput="renderTable('robo')">
<button type="button" onclick="clearFilters('robo')">Clear filters</button>
<span class="row-count" id="roboCount"></span>
</div>
<div class="table-wrap"><table id="roboTable"></table></div>
</section>

<section id="tab-config" class="section hidden">
<h2>Scan Config</h2>
<div class="note">
Depth uses the corporate model: server is level 1, share is level 2, first folder below a share is level 3. Save writes to the configured targets.json through the local config save server when it is running.
</div>
<div class="form-grid">
<div class="field">
<label for="configDefaultDepth">Default scan depth</label>
<select id="configDefaultDepth" onchange="updateConfigDefaultDepth(this.value)"></select>
</div>
<div class="field">
<label for="configDomainName">Domain name</label>
<input id="configDomainName" placeholder="corp.example.com" oninput="updateConfigField('domainName', this.value)">
</div>
<div class="field">
<label for="configDomainController">Preferred domain controller</label>
<input id="configDomainController" placeholder="dc01.corp.example.com" oninput="updateConfigField('preferredDomainController', this.value)">
</div>
<div class="field">
<label for="configNestedDepth">Nested group depth</label>
<select id="configNestedDepth" onchange="updateConfigField('maxNestedGroupDepth', Number(this.value))"></select>
</div>
</div>
<div class="form-grid">
<div class="field">
<label for="configKnownServers">Known servers</label>
<textarea id="configKnownServers" placeholder="FS01&#10;FS02" oninput="updateConfigTextLists()"></textarea>
</div>
<div class="field">
<label for="configSubnets">Subnets</label>
<textarea id="configSubnets" placeholder="10.10.20.0/24&#10;10.10.30.0/24" oninput="updateConfigTextLists()"></textarea>
</div>
</div>
<div class="controls">
<button type="button" onclick="saveConfigFile()">Save targets.json</button>
<button type="button" onclick="downloadConfigFile()">Download targets.json</button>
<button type="button" onclick="copyConfigJson()">Copy JSON</button>
<button type="button" onclick="copyRerunCommand()">Copy rerun command</button>
<span class="status-line" id="configStatus"></span>
</div>
<div class="table-wrap"><table id="configTable" class="config-table"></table></div>
</section>

<section id="tab-files" class="section hidden">
<h2>Output Files</h2>
<div class="controls">
<input id="filesSearch" placeholder="Search output files..." oninput="renderTable('files')">
<button type="button" onclick="clearFilters('files')">Clear filters</button>
<span class="row-count" id="filesCount"></span>
</div>
<div class="table-wrap"><table id="filesTable"></table></div>
</section>
</main>

<script id="fst-data" type="text/plain">
__FST_DATA_PLACEHOLDER__
</script>
<script>
let DATA = null;

function esc(v) {
if (v === null || v === undefined) return "";
return String(v).replace(/[&<>"']/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[s]));
}

function count(arr, fn) { return (arr || []).filter(fn).length; }
function hasRisk(r, text) { return (r.RiskFlags || r.Reasons || "").includes(text); }
function rowsOf(value) {
if (Array.isArray(value)) return value;
if (value === null || value === undefined) return [];
return [value];
}

function suggestedFixForRow(row) {
const flags = String(row.RiskFlags || "");
const status = String(row.ScanStatus || row.Status || "");
const error = String(row.Error || "");
const advice = [];

if (status === "Failed" || /AclReadDenied|EnumerationFailed/.test(flags) || /Access is denied|UnauthorizedAccess|permission/i.test(error)) {
advice.push("Access denied: do not reset ACLs. Back up permissions with icacls /save, run elevated or as local admin/SYSTEM, then take ownership only on the affected object and add a temporary admin ACE if needed.");
}
if (/PathNotFound/.test(flags)) advice.push("Verify the share path, mount point, DFS target, and account visibility before changing permissions.");
if (/OrphanedSID/.test(flags)) advice.push("Identify whether the SID is obsolete or migrated. Remove only that ACE after backup, or replace it with the correct current group.");
if (/BrokenInheritance/.test(flags)) advice.push("Review why inheritance is disabled. If it should follow the parent, document explicit ACEs, back up ACLs, then re-enable inheritance deliberately.");
if (/BroadPrincipal/.test(flags)) advice.push("Replace broad principals with the smallest approved domain group after validating share and NTFS permissions together.");
if (/DenyACE/.test(flags)) advice.push("Confirm the deny is intentional. Prefer removing a user from an allow group instead of relying on deny ACEs.");
if (/FullControlACE/.test(flags)) advice.push("Reduce Full Control to Modify or Read/Execute for normal users; reserve Full Control for service/admin groups.");
if (/PossibleDirectUserOrNonStandardGroup/.test(flags)) advice.push("Move access to a role-based group, validate, then remove the direct user or non-standard ACE.");

if (advice.length === 0 && flags) advice.push("Review manually. Back up ACLs first and prefer additive test changes over replacing the whole DACL.");
return [...new Set(advice)].join(" ");
}

function ensureSuggestedFixes() {
rowsOf(DATA.ntfsAcls).forEach(row => {
if (!row.SuggestedFix) row.SuggestedFix = suggestedFixForRow(row);
});
rowsOf(DATA.userAccess).forEach(row => {
if (!row.SuggestedFix) row.SuggestedFix = suggestedFixForRow(row);
});
}

function decodeBase64Utf8(value) {
const binary = atob(String(value || "").trim());
if (window.TextDecoder) {
const bytes = new Uint8Array(binary.length);
for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
return new TextDecoder("utf-8").decode(bytes);
}

let escaped = "";
for (let i = 0; i < binary.length; i++) {
escaped += "%" + ("00" + binary.charCodeAt(i).toString(16)).slice(-2);
}
return decodeURIComponent(escaped);
}

function renderCards() {
const shares = rowsOf(DATA.shares);
const acls = rowsOf(DATA.ntfsAcls);
const risk = rowsOf(DATA.risk);
const diagnostics = rowsOf(DATA.accessDiagnostics);
const servers = new Set([
...shares.map(r => r.Server),
...rowsOf(DATA.summary).map(r => r.Server)
].filter(Boolean));

const cards = [
["Servers", servers.size || 1, ""],
["Total Shares", shares.length, ""],
["ACL Rows", acls.length, ""],
["Failed ACL Rows", count(acls, r => r.ScanStatus === "Failed"), "warn"],
["Access Diagnostics", diagnostics.length, diagnostics.length ? "warn" : "ok"],
["Critical Risk", count(risk, r => r.RiskLevel === "Critical"), "bad"],
["High Risk", count(risk, r => r.RiskLevel === "High"), "bad"],
["Medium Risk", count(risk, r => r.RiskLevel === "Medium"), "warn"],
["Low Risk", count(risk, r => r.RiskLevel === "Low"), "ok"],
["Broad ACLs", count(acls, r => hasRisk(r, "BroadPrincipal")), "warn"],
["Broken Inheritance", count(acls, r => hasRisk(r, "BrokenInheritance")), "warn"],
["Orphaned SIDs", count(acls, r => hasRisk(r, "OrphanedSID")), "bad"],
["Possible Direct Users", count(acls, r => hasRisk(r, "PossibleDirectUserOrNonStandardGroup")), "warn"]
];

document.getElementById("cards").innerHTML = cards.map(c =>
`<div class="card"><div>${c[0]}</div><div class="num ${c[2]}">${c[1]}</div></div>`
).join("");
}

const CORE_FILE_ROWS = [
{File:"Dashboard.html", Description:"Self-contained browser dashboard"},
{File:"data.json", Description:"Embedded dashboard data source"},
{File:"FileShareToolkit.log", Description:"Toolkit run log"},
{File:"Start-ConfigSaveServer.cmd", Description:"Starts the localhost config save endpoint"},
{File:"ConfigSaveServer.ps1", Description:"Local PowerShell endpoint that overwrites targets.json from the dashboard Save button"}
];

const LEGACY_CSV_FILE_ROWS = [
{File:"Summary.csv", Description:"Run summary and row counts"},
{File:"SMB_Shares.csv", Description:"Discovered SMB shares"},
{File:"SMB_Share_Permissions.csv", Description:"Share-level permissions"},
{File:"NTFS_ACLs.csv", Description:"NTFS ACL inventory"},
{File:"Access_Diagnostics.csv", Description:"Aggregated access failure diagnostics and repair advice"},
{File:"Migration_Risk_Assessment.csv", Description:"Risk scores and reasons"},
{File:"User_Access.csv", Description:"Flattened principal access view"},
{File:"Robocopy_Migration_Plan.csv", Description:"Generated robocopy commands"}
];

function outputFileRows() {
const rows = CORE_FILE_ROWS.slice();
if (DATA && DATA.meta && DATA.meta.exportCsvFiles) {
LEGACY_CSV_FILE_ROWS.forEach(row => rows.push(row));
}
return rows;
}

const TABLE_STATE = {};
const RENDERED_ROWS = {};
const SELECTED_USERS = new Set();
let CONFIG_STATE = null;

const TABLES = {
risk: {
tableId:"riskTable", searchId:"riskSearch", countId:"riskCount",
rows:() => rowsOf(DATA.risk),
defaultSort:{key:"RiskScore", dir:"desc"},
cols:[
{key:"Server", title:"Server"}, {key:"ShareName", title:"Share"},
{key:"SharePath", title:"Path"}, {key:"UNCPath", title:"UNC"},
{key:"RiskScore", title:"Score"}, {key:"RiskLevel", title:"Level"},
{key:"Reasons", title:"Reasons"}
]
},
shares: {
tableId:"shareTable", searchId:"shareSearch", countId:"sharesCount",
rows:() => rowsOf(DATA.shares),
defaultSort:{key:"ShareName", dir:"asc"},
cols:[
{key:"Server", title:"Server"}, {key:"ShareName", title:"Share"},
{key:"SharePath", title:"Path"}, {key:"UNCPath", title:"UNC"},
{key:"ConfiguredScanDepth", title:"Scan Depth"}, {key:"ScanDepthSource", title:"Depth Source"},
{key:"SizeGB", title:"GB"}, {key:"FileCount", title:"Files"},
{key:"FolderCount", title:"Folders"}, {key:"Description", title:"Description"},
{key:"ShareState", title:"State"}, {key:"EncryptData", title:"Encrypted"}
]
},
acls: {
tableId:"aclTable", searchId:"aclSearch", countId:"aclsCount", limitId:"aclLimit",
rows:() => rowsOf(DATA.ntfsAcls),
baseFilter:r => (r.RiskFlags && String(r.RiskFlags).trim() !== "") || r.ScanStatus === "Failed",
defaultSort:{key:"RiskFlags", dir:"asc"},
cols:[
{key:"Server", title:"Server"}, {key:"ShareName", title:"Share"},
{key:"ItemPath", title:"Item"}, {key:"Depth", title:"Depth"},
{key:"ScanDepth", title:"Scan Depth"},
{key:"IdentityReference", title:"Identity"}, {key:"AccessControlType", title:"Type"},
{key:"FileSystemRights", title:"Rights"}, {key:"IsInherited", title:"Inherited"},
{key:"RiskFlags", title:"Risk"}, {key:"SuggestedFix", title:"Suggested Fix"},
{key:"ScanStatus", title:"Status"}, {key:"Error", title:"Error"}
]
},
diag: {
tableId:"diagTable", searchId:"diagSearch", countId:"diagCount",
rows:() => rowsOf(DATA.accessDiagnostics),
defaultSort:{key:"FailureCount", dir:"desc"},
cols:[
{key:"Server", title:"Server"}, {key:"ShareName", title:"Share"},
{key:"ScopePath", title:"Scope"}, {key:"Depth", title:"Depth"},
{key:"FailureCount", title:"Failures"}, {key:"RiskFlags", title:"Risk"},
{key:"ErrorSignature", title:"Error Type"}, {key:"PathType", title:"Path Type"},
{key:"CanReadAcl", title:"ACL Readable"}, {key:"CanEnumerate", title:"Enumerable"},
{key:"Owner", title:"Owner"}, {key:"UnresolvedAceCount", title:"Unresolved ACEs"},
{key:"LocalIdentityCount", title:"Local ACEs"}, {key:"SampleFile", title:"Sample File"},
{key:"SampleFileErrors", title:"Sample Errors"}, {key:"RobocopyStatus", title:"Robocopy"},
{key:"RecommendedCopyMode", title:"Copy Mode"}, {key:"DatExitCode", title:"DAT"},
{key:"DatsExitCode", title:"DATS"}, {key:"DatsoExitCode", title:"DATSO"},
{key:"LikelyCause", title:"Likely Cause"}, {key:"RecommendedFix", title:"Recommended Fix"},
{key:"RobocopyReportPath", title:"Report"}, {key:"RobocopyLogRoot", title:"Logs"}
]
},
perms: {
tableId:"permTable", searchId:"permSearch", countId:"permsCount",
rows:() => rowsOf(DATA.sharePermissions),
defaultSort:{key:"AccountName", dir:"asc"},
cols:[
{key:"Server", title:"Server"}, {key:"ShareName", title:"Share"},
{key:"AccountName", title:"Account"}, {key:"AccessControlType", title:"Type"},
{key:"AccessRight", title:"Right"}, {key:"Status", title:"Status"}, {key:"Error", title:"Error"}
]
},
users: {
tableId:"userAccessTable", searchId:"userAccessSearch", countId:"usersCount",
rows:() => rowsOf(DATA.userAccess),
userFilter:true,
defaultSort:{key:"Principal", dir:"asc"},
cols:[
{key:"Principal", title:"User or Group"}, {key:"AccessSource", title:"Source"},
{key:"Server", title:"Server"}, {key:"ShareName", title:"Share"},
{key:"SharePath", title:"Share Path"}, {key:"ItemPath", title:"Item"},
{key:"AccessControlType", title:"Type"}, {key:"AccessRights", title:"Rights"},
{key:"IsInherited", title:"Inherited"}, {key:"RiskFlags", title:"Risk"},
{key:"SuggestedFix", title:"Suggested Fix"}, {key:"Status", title:"Status"}, {key:"Error", title:"Error"}
]
},
robo: {
tableId:"roboTable", searchId:"roboSearch", countId:"roboCount",
rows:() => rowsOf(DATA.robocopyPlan),
defaultSort:{key:"ShareName", dir:"asc"},
copyKey:"RobocopyCommand",
cols:[
{key:"SourceServer", title:"Source Server"}, {key:"ShareName", title:"Share"},
{key:"SourceUNC", title:"Source"}, {key:"TargetUNC", title:"Target"},
{key:"LogPath", title:"Log"}, {key:"RobocopyCommand", title:"Command"}
]
},
files: {
tableId:"filesTable", searchId:"filesSearch", countId:"filesCount",
rows:() => outputFileRows(),
defaultSort:{key:"File", dir:"asc"},
cols:[
{key:"File", title:"File", link:true},
{key:"Description", title:"Description"}
]
}
};

function escAttr(v) {
return esc(v);
}

function getState(name) {
if (!TABLE_STATE[name]) {
const cfg = TABLES[name];
TABLE_STATE[name] = {
sortKey: cfg.defaultSort ? cfg.defaultSort.key : null,
sortDir: cfg.defaultSort ? cfg.defaultSort.dir : "asc",
filters: {}
};
}
return TABLE_STATE[name];
}

function getCell(row, col) {
if (col.value) return col.value(row);
return row[col.key];
}

function matchesText(value, q) {
if (!q) return true;
if (value === null || value === undefined) return false;
return String(value).toLowerCase().includes(q);
}

function matchesGlobalSearch(row, cols, q) {
if (!q) return true;
return cols.some(col => matchesText(getCell(row, col), q));
}

function matchesColumnFilters(row, cols, filters) {
return cols.every(col => matchesText(getCell(row, col), String(filters[col.key] || "").toLowerCase()));
}

function compareCellValues(a, b) {
const aText = a === null || a === undefined ? "" : String(a);
const bText = b === null || b === undefined ? "" : String(b);
const aNum = Number(aText.replace(/,/g, ""));
const bNum = Number(bText.replace(/,/g, ""));

if (aText !== "" && bText !== "" && !Number.isNaN(aNum) && !Number.isNaN(bNum)) {
return aNum - bNum;
}

return aText.localeCompare(bText, undefined, {numeric:true, sensitivity:"base"});
}

function cellHtml(row, col) {
const value = getCell(row, col);
if (col.link) {
return '<a href="' + escAttr(value) + '">' + esc(value) + '</a>';
}
return esc(value);
}

function getLimit(cfg) {
if (!cfg.limitId) return null;
const el = document.getElementById(cfg.limitId);
if (!el) return null;
const limit = Number(el.value);
return Number.isFinite(limit) && limit > 0 ? limit : null;
}

function updateCount(cfg, visible, total) {
const el = document.getElementById(cfg.countId);
if (!el) return;
el.textContent = visible === total ? visible + " rows" : visible + " of " + total + " rows";
}

function renderTable(name) {
const cfg = TABLES[name];
if (!cfg || !DATA) return;

const state = getState(name);
const searchEl = document.getElementById(cfg.searchId);
const q = searchEl ? searchEl.value.trim().toLowerCase() : "";
let rows = rowsOf(cfg.rows()).slice();

if (cfg.baseFilter) rows = rows.filter(cfg.baseFilter);
if (cfg.userFilter && SELECTED_USERS.size > 0) {
rows = rows.filter(row => SELECTED_USERS.has(String(row.Principal || "")));
}

rows = rows
.filter(row => matchesGlobalSearch(row, cfg.cols, q))
.filter(row => matchesColumnFilters(row, cfg.cols, state.filters));

if (state.sortKey) {
const sortCol = cfg.cols.find(col => col.key === state.sortKey);
if (sortCol) {
rows = rows.slice().sort((a, b) => {
const result = compareCellValues(getCell(a, sortCol), getCell(b, sortCol));
return state.sortDir === "desc" ? -result : result;
});
}
}

const total = rows.length;
const limit = getLimit(cfg);
if (limit) rows = rows.slice(0, limit);
RENDERED_ROWS[name] = rows;

let html = "<thead><tr>";
cfg.cols.forEach(col => {
const marker = state.sortKey === col.key ? (state.sortDir === "asc" ? " ^" : " v") : "";
html += '<th><button type="button" class="sortbtn" onclick="sortTable(\'' + name + '\',\'' + col.key + '\')">' + esc(col.title + marker) + '</button></th>';
});
if (cfg.copyKey) html += "<th>Copy</th>";
html += '</tr><tr class="filter-row">';
cfg.cols.forEach(col => {
html += '<th><input class="column-filter" value="' + escAttr(state.filters[col.key] || "") + '" placeholder="' + escAttr(col.title) + '" oninput="setColumnFilter(\'' + name + '\',\'' + col.key + '\', this.value)"></th>';
});
if (cfg.copyKey) html += "<th></th>";
html += "</tr></thead><tbody>";

if (rows.length === 0) {
html += '<tr><td colspan="' + (cfg.cols.length + (cfg.copyKey ? 1 : 0)) + '">No data found</td></tr>';
} else {
rows.forEach((row, idx) => {
html += "<tr>" + cfg.cols.map(col => "<td>" + cellHtml(row, col) + "</td>").join("");
if (cfg.copyKey) {
html += '<td><button class="copybtn" type="button" onclick="copyText(\'' + name + '\',' + idx + ',\'' + cfg.copyKey + '\')">Copy</button></td>';
}
html += "</tr>";
});
}

html += "</tbody>";
document.getElementById(cfg.tableId).innerHTML = html;
updateCount(cfg, rows.length, total);
}

function sortTable(name, key) {
const state = getState(name);
if (state.sortKey === key) {
state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
} else {
state.sortKey = key;
state.sortDir = "asc";
}
renderTable(name);
}

function setColumnFilter(name, key, value) {
const state = getState(name);
state.filters[key] = value;
renderTable(name);
}

function clearFilters(name) {
const cfg = TABLES[name];
const state = getState(name);
state.filters = {};

const searchEl = document.getElementById(cfg.searchId);
if (searchEl) searchEl.value = "";

if (name === "users") {
SELECTED_USERS.clear();
updateUserFilterButton();
renderUserDropdown();
}

renderTable(name);
}

function copyText(name, idx, key) {
const rows = RENDERED_ROWS[name] || [];
const val = rows[idx] ? rows[idx][key] : "";
if (navigator.clipboard) navigator.clipboard.writeText(val);
else window.prompt("Copy:", val);
}

function renderRisk() { renderTable("risk"); }
function renderShares() { renderTable("shares"); }
function renderAcls() { renderTable("acls"); }
function renderPerms() { renderTable("perms"); }
function renderRobo() { renderTable("robo"); }

function renderAllTables() {
Object.keys(TABLES).forEach(renderTable);
}

function safeFileName(value) {
return String(value || "FileShareToolkit")
.replace(/[\\/:*?"<>|]+/g, "_")
.replace(/\s+/g, "_")
.replace(/^_+|_+$/g, "") || "FileShareToolkit";
}

function exportFileBaseName() {
const meta = DATA ? DATA.meta || {} : {};
const server = safeFileName(meta.server || "Dashboard");
const run = safeFileName(meta.runId || new Date().toISOString().slice(0, 19));
return "FileShareToolkit_" + server + "_" + run;
}

function downloadTextFile(filename, content, mimeType) {
const blob = new Blob([content], {type:mimeType});
const url = URL.createObjectURL(blob);
const link = document.createElement("a");
link.href = url;
link.download = filename;
document.body.appendChild(link);
link.click();
link.remove();
URL.revokeObjectURL(url);
}

function exportDatasets() {
ensureUserAccessRows();
return [
{name:"Summary", rows:rowsOf(DATA.summary)},
{name:"Shares", rows:rowsOf(DATA.shares)},
{name:"SharePermissions", rows:rowsOf(DATA.sharePermissions)},
{name:"NtfsAcls", rows:rowsOf(DATA.ntfsAcls)},
{name:"AccessDiagnostics", rows:rowsOf(DATA.accessDiagnostics)},
{name:"Risk", rows:rowsOf(DATA.risk)},
{name:"UserAccess", rows:rowsOf(DATA.userAccess)},
{name:"RobocopyPlan", rows:rowsOf(DATA.robocopyPlan)},
{name:"SourceFiles", rows:rowsOf(DATA.sourceFiles)}
];
}

function valueForExport(value) {
if (value === null || value === undefined) return "";
if (typeof value === "object") return JSON.stringify(value);
return String(value);
}

function csvCell(value) {
const text = valueForExport(value);
if (/[",\r\n]/.test(text)) return '"' + text.replace(/"/g, '""') + '"';
return text;
}

function preferredColumns(keys) {
const preferred = [
"Dataset","RunId","Server","ShareName","SharePath","UNCPath","ItemPath","ScopePath","Depth","ScanDepth",
"Principal","IdentityReference","AccountName","AccessSource","AccessControlType","AccessRight",
"AccessRights","FileSystemRights","IsInherited","RiskLevel","RiskScore","RiskFlags","SuggestedFix","Reasons",
"FailureCount","ErrorSignature","LikelyCause","RecommendedFix","ScanStatus","Status","Error","OriginalError",
"RobocopyStatus","RecommendedCopyMode","DatExitCode","DatsExitCode","DatsoExitCode","RobocopyReportPath",
"SourceUNC","TargetUNC","RobocopyCommand"
];
const seen = {};
const ordered = [];
preferred.forEach(key => {
if (keys.indexOf(key) >= 0 && !seen[key]) {
seen[key] = true;
ordered.push(key);
}
});
keys.sort((a, b) => a.localeCompare(b, undefined, {numeric:true, sensitivity:"base"})).forEach(key => {
if (!seen[key]) {
seen[key] = true;
ordered.push(key);
}
});
return ordered;
}

function exportCompleteCsv() {
const datasets = exportDatasets();
const rows = [];
const keys = ["Dataset"];

datasets.forEach(dataset => {
(dataset.rows || []).forEach(row => {
const output = Object.assign({Dataset:dataset.name}, row || {});
Object.keys(output).forEach(key => {
if (keys.indexOf(key) < 0) keys.push(key);
});
rows.push(output);
});
});

const columns = preferredColumns(keys);
let csv = columns.map(csvCell).join(",") + "\r\n";
rows.forEach(row => {
csv += columns.map(key => csvCell(row[key])).join(",") + "\r\n";
});

downloadTextFile(exportFileBaseName() + "_complete.csv", csv, "text/csv;charset=utf-8");
}

function xmlEsc(value) {
return valueForExport(value)
.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, "")
.replace(/&/g, "&amp;")
.replace(/</g, "&lt;")
.replace(/>/g, "&gt;")
.replace(/"/g, "&quot;");
}

function worksheetName(value, used) {
let name = String(value || "Sheet").replace(/[:\\\/?\*\[\]]/g, "_").slice(0, 31) || "Sheet";
let finalName = name;
let i = 2;
while (used[finalName]) {
const suffix = "_" + i;
finalName = name.slice(0, 31 - suffix.length) + suffix;
i++;
}
used[finalName] = true;
return finalName;
}

function exportExcelWorkbook() {
const datasets = exportDatasets();
const usedNames = {};
let workbook = '<?xml version="1.0"?>\n';
workbook += '<?mso-application progid="Excel.Sheet"?>\n';
workbook += '<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" ';
workbook += 'xmlns:o="urn:schemas-microsoft-com:office:office" ';
workbook += 'xmlns:x="urn:schemas-microsoft-com:office:excel" ';
workbook += 'xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet" ';
workbook += 'xmlns:html="http://www.w3.org/TR/REC-html40">\n';

datasets.forEach(dataset => {
const rows = dataset.rows || [];
const keys = [];
rows.forEach(row => {
Object.keys(row || {}).forEach(key => {
if (keys.indexOf(key) < 0) keys.push(key);
});
});
const columns = preferredColumns(keys);
workbook += '<Worksheet ss:Name="' + xmlEsc(worksheetName(dataset.name, usedNames)) + '"><Table>\n';
if (columns.length === 0) {
workbook += '<Row><Cell><Data ss:Type="String">No rows</Data></Cell></Row>\n';
}
else {
workbook += '<Row>' + columns.map(key => '<Cell><Data ss:Type="String">' + xmlEsc(key) + '</Data></Cell>').join("") + '</Row>\n';
rows.forEach(row => {
workbook += '<Row>' + columns.map(key => '<Cell><Data ss:Type="String">' + xmlEsc(row ? row[key] : "") + '</Data></Cell>').join("") + '</Row>\n';
});
}
workbook += '</Table></Worksheet>\n';
});

workbook += '</Workbook>';
downloadTextFile(exportFileBaseName() + "_complete.xls", workbook, "application/vnd.ms-excel;charset=utf-8");
}

function exportPdf() {
setConfigStatus("");
window.print();
}

function depthValues() {
const values = [];
for (let i = 2; i <= 12; i++) values.push(i);
return values;
}

function depthLabel(value) {
const n = Number(value);
if (n === 2) return "2 - share root";
if (n === 3) return "3 - first folder";
return String(n) + " levels";
}

function numberOr(value, fallback) {
const n = Number(value);
return Number.isFinite(n) ? n : fallback;
}

function normalizeList(value) {
if (Array.isArray(value)) {
return value.map(v => String(v || "").trim()).filter(Boolean);
}
if (typeof value === "string") {
return value.split(/[\n,;]+/).map(v => v.trim()).filter(Boolean);
}
return [];
}

function asArray(value) {
if (Array.isArray(value)) return value;
if (value === null || value === undefined) return [];
return [value];
}

function uniqueSorted(values) {
const seen = {};
normalizeList(values).forEach(value => { seen[value] = true; });
return Object.keys(seen).sort((a, b) => a.localeCompare(b, undefined, {numeric:true, sensitivity:"base"}));
}

function depthOptions(selected) {
return depthValues().map(value =>
'<option value="' + value + '"' + (Number(selected) === value ? " selected" : "") + '>' + esc(depthLabel(value)) + '</option>'
).join("");
}

function nestedDepthOptions(selected) {
let html = "";
for (let i = 1; i <= 10; i++) {
html += '<option value="' + i + '"' + (Number(selected) === i ? " selected" : "") + '>' + i + '</option>';
}
return html;
}

function ensureTarget(targets, server, defaultDepth) {
let target = targets.find(row => String(row.server || "").toLowerCase() === String(server || "").toLowerCase());
if (!target) {
target = {server:String(server || ""), scanDepth:defaultDepth, shares:[]};
targets.push(target);
}
if (!Array.isArray(target.shares)) target.shares = [];
return target;
}

function ensureShare(target, shareName, uncPath, defaultDepth) {
let share = target.shares.find(row => String(row.name || "").toLowerCase() === String(shareName || "").toLowerCase());
if (!share) {
share = {name:String(shareName || ""), uncPath:String(uncPath || ""), scanDepth:defaultDepth};
target.shares.push(share);
}
if (!share.uncPath && uncPath) share.uncPath = String(uncPath);
return share;
}

function buildInitialConfigState() {
const existing = DATA.scanConfig || {};
const meta = DATA.meta || {};
const metaDepth = numberOr(meta.configDefaultScanDepth, numberOr(meta.maxAclDepth, 3) + 2);
const defaultDepth = numberOr(existing.defaultAclDepth, numberOr(metaDepth, 5));
const domain = existing.domain || {};
const targets = [];

asArray(existing.targets).forEach(existingTarget => {
const server = String(existingTarget.server || existingTarget.name || "").trim();
if (!server) return;
const target = ensureTarget(targets, server, numberOr(existingTarget.scanDepth, defaultDepth));
target.scanDepth = numberOr(existingTarget.scanDepth, defaultDepth);
asArray(existingTarget.shares).forEach(existingShare => {
const name = String(existingShare.name || existingShare.shareName || "").trim();
if (!name) return;
const share = ensureShare(target, name, existingShare.uncPath || "", target.scanDepth);
share.scanDepth = numberOr(existingShare.scanDepth, target.scanDepth);
});
});

rowsOf(DATA.shares).forEach(row => {
const server = String(row.Server || meta.server || "").trim();
const shareName = String(row.ShareName || "").trim();
if (!server || !shareName) return;
const target = ensureTarget(targets, server, defaultDepth);
const share = ensureShare(target, shareName, row.UNCPath || "", target.scanDepth);
share.scanDepth = numberOr(row.ConfiguredScanDepth, numberOr(share.scanDepth, defaultDepth));
});

const knownServers = uniqueSorted([
...targets.map(target => target.server),
...normalizeList(existing.knownServers),
...rowsOf(DATA.summary).map(row => row.Server || "")
]);

return {
version: 1,
depthCounting: "Server=1;Share=2;FirstFolder=3",
defaultAclDepth: defaultDepth,
domain: {
enabled: domain.enabled !== false,
domainName: domain.domainName || "",
preferredDomainController: domain.preferredDomainController || "",
resolveNestedGroups: domain.resolveNestedGroups !== false,
maxNestedGroupDepth: numberOr(domain.maxNestedGroupDepth, 5),
cacheIdentityLookups: domain.cacheIdentityLookups !== false
},
knownServers,
subnets: uniqueSorted(existing.subnets || []),
targets
};
}

function ensureConfigState() {
if (!CONFIG_STATE) CONFIG_STATE = buildInitialConfigState();
return CONFIG_STATE;
}

function setConfigStatus(message) {
const el = document.getElementById("configStatus");
if (el) el.textContent = message || "";
}

function updateConfigTextLists() {
const state = ensureConfigState();
const serversEl = document.getElementById("configKnownServers");
const subnetsEl = document.getElementById("configSubnets");
if (serversEl) state.knownServers = uniqueSorted(serversEl.value);
if (subnetsEl) state.subnets = uniqueSorted(subnetsEl.value);
}

function updateConfigDefaultDepth(value) {
const state = ensureConfigState();
const oldDepth = state.defaultAclDepth;
const newDepth = numberOr(value, state.defaultAclDepth);
state.defaultAclDepth = newDepth;
state.targets.forEach(target => {
if (!target.scanDepth || Number(target.scanDepth) === Number(oldDepth)) target.scanDepth = newDepth;
(target.shares || []).forEach(share => {
if (!share.scanDepth || Number(share.scanDepth) === Number(oldDepth)) share.scanDepth = newDepth;
});
});
renderScanConfig();
setConfigStatus("Default depth updated. Save targets.json before rerunning PowerShell.");
}

function updateConfigField(field, value) {
const state = ensureConfigState();
if (field === "maxNestedGroupDepth") state.domain[field] = numberOr(value, 5);
else state.domain[field] = value;
setConfigStatus("Config updated. Save targets.json before rerunning PowerShell.");
}

function updateShareDepth(server, shareName, value) {
const state = ensureConfigState();
const target = ensureTarget(state.targets, server, state.defaultAclDepth);
const share = ensureShare(target, shareName, "", target.scanDepth || state.defaultAclDepth);
share.scanDepth = numberOr(value, state.defaultAclDepth);
renderScanConfig();
setConfigStatus("Share depth updated. Save targets.json before rerunning PowerShell.");
}

function configToJsonObject() {
const state = ensureConfigState();
updateConfigTextLists();

const targets = state.targets.map(target => ({
server: target.server,
scanDepth: numberOr(target.scanDepth, state.defaultAclDepth),
shares: (target.shares || []).map(share => ({
name: share.name,
uncPath: share.uncPath || "",
scanDepth: numberOr(share.scanDepth, numberOr(target.scanDepth, state.defaultAclDepth))
})).sort((a, b) => a.name.localeCompare(b.name, undefined, {numeric:true, sensitivity:"base"}))
}));

state.knownServers.forEach(server => {
if (!targets.some(target => String(target.server).toLowerCase() === String(server).toLowerCase())) {
targets.push({server, scanDepth: state.defaultAclDepth, shares: []});
}
});

targets.sort((a, b) => a.server.localeCompare(b.server, undefined, {numeric:true, sensitivity:"base"}));

return {
version: 1,
depthCounting: state.depthCounting,
defaultAclDepth: state.defaultAclDepth,
domain: state.domain,
subnets: state.subnets,
targets
};
}

function renderScanConfig() {
const state = ensureConfigState();
const meta = DATA.meta || {};
const status = document.getElementById("configStatus");
if (status && !status.textContent && meta.configTargetPath) {
status.textContent = "Save target: " + meta.configTargetPath;
}

const defaultDepth = document.getElementById("configDefaultDepth");
if (defaultDepth) defaultDepth.innerHTML = depthOptions(state.defaultAclDepth);

const nestedDepth = document.getElementById("configNestedDepth");
if (nestedDepth) nestedDepth.innerHTML = nestedDepthOptions(state.domain.maxNestedGroupDepth);

const domainName = document.getElementById("configDomainName");
if (domainName && document.activeElement !== domainName) domainName.value = state.domain.domainName || "";

const domainController = document.getElementById("configDomainController");
if (domainController && document.activeElement !== domainController) domainController.value = state.domain.preferredDomainController || "";

const knownServers = document.getElementById("configKnownServers");
if (knownServers && document.activeElement !== knownServers) knownServers.value = state.knownServers.join("\n");

const subnets = document.getElementById("configSubnets");
if (subnets && document.activeElement !== subnets) subnets.value = state.subnets.join("\n");

let html = "<thead><tr><th>Server</th><th>Share</th><th>UNC</th><th>Current Depth</th><th>New Depth</th></tr></thead><tbody>";
const rows = [];
state.targets.forEach(target => {
(target.shares || []).forEach(share => rows.push({target, share}));
});

if (rows.length === 0) {
html += '<tr><td colspan="5">No discovered shares yet. Run a first scan, or enter known servers above and download targets.json.</td></tr>';
}
else {
rows.sort((a, b) => {
const serverCompare = a.target.server.localeCompare(b.target.server, undefined, {numeric:true, sensitivity:"base"});
if (serverCompare !== 0) return serverCompare;
return a.share.name.localeCompare(b.share.name, undefined, {numeric:true, sensitivity:"base"});
}).forEach(row => {
const depth = numberOr(row.share.scanDepth, numberOr(row.target.scanDepth, state.defaultAclDepth));
html += '<tr>';
html += '<td>' + esc(row.target.server) + '</td>';
html += '<td>' + esc(row.share.name) + '</td>';
html += '<td>' + esc(row.share.uncPath || "") + '</td>';
html += '<td>' + esc(depthLabel(depth)) + '</td>';
html += '<td><select data-config-share="1" data-server="' + escAttr(row.target.server) + '" data-share="' + escAttr(row.share.name) + '">' + depthOptions(depth) + '</select></td>';
html += '</tr>';
});
}

html += "</tbody>";
const table = document.getElementById("configTable");
if (table) {
table.innerHTML = html;
table.querySelectorAll('select[data-config-share="1"]').forEach(select => {
select.addEventListener("change", () => updateShareDepth(select.dataset.server, select.dataset.share, select.value));
});
}
}

async function saveConfigFile() {
const json = JSON.stringify(configToJsonObject(), null, 2);
const endpoint = DATA && DATA.meta ? DATA.meta.localConfigSaveEndpoint : "";
if (endpoint) {
try {
const response = await fetch(endpoint, {
method: "POST",
headers: {"Content-Type": "text/plain;charset=utf-8"},
body: json
});
const text = await response.text();
if (response.ok) {
let message = "Saved targets.json.";
try {
const result = JSON.parse(text);
if (result.path) message = "Saved " + result.path;
}
catch (_) {}
setConfigStatus(message);
return;
}
setConfigStatus("Local save failed: " + text);
return;
}
catch (e) {
setConfigStatus("Local save endpoint is not running. Use the Start config save server link, then press Save again.");
return;
}
}

if (!window.showSaveFilePicker) {
downloadConfigFile();
setConfigStatus("Browser file save is unavailable here. Downloaded targets.json instead.");
return;
}

try {
const handle = await window.showSaveFilePicker({
suggestedName: "targets.json",
types: [{description: "JSON", accept: {"application/json": [".json"]}}]
});
const writable = await handle.createWritable();
await writable.write(json);
await writable.close();
setConfigStatus("Saved targets.json. Rerun PowerShell with -ConfigPath pointing to that file.");
}
catch (e) {
setConfigStatus("Save not completed: " + e.message);
}
}

function downloadConfigFile() {
const json = JSON.stringify(configToJsonObject(), null, 2);
const blob = new Blob([json], {type:"application/json"});
const url = URL.createObjectURL(blob);
const link = document.createElement("a");
link.href = url;
link.download = "targets.json";
document.body.appendChild(link);
link.click();
link.remove();
URL.revokeObjectURL(url);
setConfigStatus("Downloaded targets.json.");
}

function copyConfigJson() {
const json = JSON.stringify(configToJsonObject(), null, 2);
if (navigator.clipboard) navigator.clipboard.writeText(json);
else window.prompt("Copy targets.json:", json);
setConfigStatus("Copied targets.json JSON.");
}

function getRerunCommand() {
const meta = DATA.meta || {};
const script = meta.scriptPath || (".\\" + (meta.scriptFileName || "Invoke-FileShareToolkit_Portable_v3_2.ps1"));
const configPath = meta.configTargetPath || meta.configPath || ".\\config\\targets.json";
let command = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + script + '" -ConfigPath "' + configPath + '"';
if (meta.centralJsonPath) command += ' -CentralJsonPath "' + meta.centralJsonPath + '"';
if (meta.targetServer) command += ' -TargetServer "' + meta.targetServer + '"';
if (meta.robocopyDiagnosticDestinationRoot) command += ' -RobocopyDiagnosticDestinationRoot "' + meta.robocopyDiagnosticDestinationRoot + '"';
if (meta.skipAccessDiagnostics) command += " -SkipAccessDiagnostics";
command += " -OpenDashboard";
return command;
}

function copyRerunCommand() {
const command = getRerunCommand();
if (navigator.clipboard) navigator.clipboard.writeText(command);
else window.prompt("Copy rerun command:", command);
setConfigStatus("Copied rerun command.");
}

function showTab(name) {
document.querySelectorAll("section[id^='tab-']").forEach(e => e.classList.add("hidden"));
document.getElementById("tab-" + name).classList.remove("hidden");
document.querySelectorAll(".tab").forEach(e => e.classList.remove("active"));
const tab = [...document.querySelectorAll(".tab")].find(e => e.getAttribute("onclick") === "showTab('" + name + "')");
if (tab) tab.classList.add("active");
if (name === "config") renderScanConfig();
renderTable(name);
}

function principalValues() {
const seen = {};
const rows = DATA ? rowsOf(DATA.userAccess) : [];
rows.forEach(row => {
const principal = String(row.Principal || "");
if (principal) seen[principal] = true;
});
return Object.keys(seen).sort((a, b) => a.localeCompare(b, undefined, {numeric:true, sensitivity:"base"}));
}

function updateUserFilterButton() {
const button = document.getElementById("userFilterButton");
if (!button) return;
button.textContent = SELECTED_USERS.size === 0 ? "All users" : SELECTED_USERS.size + " selected";
}

function renderUserDropdown() {
const container = document.getElementById("userFilterOptions");
if (!container) return;

const search = document.getElementById("userOptionSearch");
const q = search ? search.value.trim().toLowerCase() : "";
const principals = principalValues().filter(principal => !q || principal.toLowerCase().includes(q));
container.innerHTML = "";

if (principals.length === 0) {
const empty = document.createElement("div");
empty.className = "muted";
empty.textContent = "No users found";
container.appendChild(empty);
return;
}

principals.forEach(principal => {
const label = document.createElement("label");
label.className = "check-row";

const checkbox = document.createElement("input");
checkbox.type = "checkbox";
checkbox.checked = SELECTED_USERS.has(principal);
checkbox.addEventListener("change", () => {
if (checkbox.checked) SELECTED_USERS.add(principal);
else SELECTED_USERS.delete(principal);
updateUserFilterButton();
renderTable("users");
});

const text = document.createElement("span");
text.textContent = principal;

label.appendChild(checkbox);
label.appendChild(text);
container.appendChild(label);
});
}

function clearUserSelection() {
SELECTED_USERS.clear();
updateUserFilterButton();
renderUserDropdown();
renderTable("users");
}

function toggleUserDropdown() {
const menu = document.getElementById("userFilterMenu");
if (!menu) return;
menu.classList.toggle("hidden");
if (!menu.classList.contains("hidden")) renderUserDropdown();
}

function ensureUserAccessRows() {
if (DATA.userAccess !== null && DATA.userAccess !== undefined) {
DATA.userAccess = rowsOf(DATA.userAccess);
return;
}

const rows = [];
const shareByName = {};
rowsOf(DATA.shares).forEach(share => {
if (share.ShareName) shareByName[share.ShareName] = share;
});

rowsOf(DATA.sharePermissions).forEach(perm => {
if (!perm.AccountName) return;
const share = shareByName[perm.ShareName] || {};
rows.push({
Principal: perm.AccountName,
AccessSource: "SharePermission",
Server: perm.Server,
ShareName: perm.ShareName,
SharePath: share.SharePath || "",
ItemPath: share.UNCPath || "",
AccessControlType: perm.AccessControlType,
AccessRights: perm.AccessRight,
IsInherited: "",
RiskFlags: /Everyone|Authenticated Users|BUILTIN\\Users/.test(perm.AccountName) ? "BroadPrincipal" : "",
SuggestedFix: "",
Status: perm.Status,
Error: perm.Error
});
});

rowsOf(DATA.ntfsAcls).forEach(acl => {
if (!acl.IdentityReference) return;
rows.push({
Principal: acl.IdentityReference,
AccessSource: "NTFS",
Server: acl.Server,
ShareName: acl.ShareName,
SharePath: acl.SharePath,
ItemPath: acl.ItemPath,
AccessControlType: acl.AccessControlType,
AccessRights: acl.FileSystemRights,
IsInherited: acl.IsInherited,
RiskFlags: acl.RiskFlags,
SuggestedFix: acl.SuggestedFix || "",
Status: acl.ScanStatus,
Error: acl.Error
});
});

DATA.userAccess = rows;
}

document.addEventListener("click", event => {
const dropdown = document.querySelector(".dropdown");
const menu = document.getElementById("userFilterMenu");
if (dropdown && menu && !dropdown.contains(event.target)) {
menu.classList.add("hidden");
}
});

function load() {
try {
const raw = decodeBase64Utf8(document.getElementById("fst-data").textContent);
DATA = JSON.parse(raw);
ensureUserAccessRows();
ensureSuggestedFixes();
const sourceText = DATA.meta.sourceJsonFiles ? ` | JSON files: ${DATA.meta.sourceJsonFiles}` : "";
document.getElementById("subtitle").textContent = `Scope: ${DATA.meta.server} | Generated: ${DATA.meta.generatedAt} | Run: ${DATA.meta.runId}${sourceText}`;
const commandLink = DATA.meta.generateCentralDashboardCommand || "";
if (commandLink) {
document.getElementById("centralGenerateLink").href = commandLink;
document.getElementById("centralActions").classList.remove("hidden");
}
const helperLink = DATA.meta.localConfigSaveServerCommand || "";
if (helperLink) {
document.getElementById("configHelperLink").href = helperLink;
document.getElementById("configHelperActions").classList.remove("hidden");
}
renderCards(); renderAllTables(); updateUserFilterButton(); renderUserDropdown();
} catch (e) {
document.getElementById("subtitle").textContent = "Failed to load embedded dashboard data: " + e;
}
}
load();
</script>
</body>
</html>
'@

Set-Content -Path $HtmlPath -Value $html -Encoding UTF8
}

function Get-ObjectPropertyValue {
param(
[object]$Object,
[string]$Name
)

if ($null -eq $Object) { return $null }

if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name)) {
return $Object[$Name]
}

$property = $Object.PSObject.Properties[$Name]
if ($null -eq $property) { return $null }

return $property.Value
}

function Get-JsonArrayProperty {
param(
[object]$Object,
[string]$Name
)

$value = Get-ObjectPropertyValue -Object $Object -Name $Name
if ($null -eq $value) { return @() }

return @($value)
}

function Get-ConfigArrayProperty {
param(
[object]$Object,
[string]$Name
)

$value = Get-ObjectPropertyValue -Object $Object -Name $Name
if ($null -eq $value) { return @() }
return @($value)
}

function Get-OptionalIntProperty {
param(
[object]$Object,
[string]$Name
)

$value = Get-ObjectPropertyValue -Object $Object -Name $Name
if ($null -eq $value) { return $null }

$parsed = 0
if ([int]::TryParse([string]$value, [ref]$parsed)) {
return $parsed
}

return $null
}

function Convert-ScanDepthToAclDepth {
param([int]$ScanDepth)

if ($ScanDepth -le 2) { return 0 }
return ($ScanDepth - 2)
}

function Convert-AclDepthToScanDepth {
param([int]$AclDepth)

if ($AclDepth -lt 0) { return 2 }
return ($AclDepth + 2)
}

function Read-ToolkitConfig {
param([string]$Path)

if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

try {
if (-not (Test-Path -LiteralPath $Path)) {
Write-Log "Config path was supplied but does not exist: $Path" "WARN"
return $null
}

$raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
if ([string]::IsNullOrWhiteSpace($raw)) {
Write-Log "Config path is empty: $Path" "WARN"
return $null
}

return ($raw | ConvertFrom-Json)
}
catch {
Write-Log "Could not read config file $Path. Error: $($_.Exception.Message)" "WARN"
return $null
}
}

function Find-TargetConfig {
param(
[object]$Config,
[string]$ServerName
)

if ($null -eq $Config -or [string]::IsNullOrWhiteSpace($ServerName)) { return $null }

foreach ($target in @(Get-ConfigArrayProperty -Object $Config -Name "targets")) {
$candidate = [string](Get-ObjectPropertyValue -Object $target -Name "server")
if ([string]::IsNullOrWhiteSpace($candidate)) {
$candidate = [string](Get-ObjectPropertyValue -Object $target -Name "name")
}

if ([string]::Equals($candidate, $ServerName, [System.StringComparison]::OrdinalIgnoreCase)) {
return $target
}
}

return $null
}

function Find-ShareConfig {
param(
[object]$TargetConfig,
[object]$Share
)

if ($null -eq $TargetConfig -or $null -eq $Share) { return $null }

$shareName = [string]$Share.ShareName
$uncPath = [string]$Share.UNCPath

foreach ($shareConfig in @(Get-ConfigArrayProperty -Object $TargetConfig -Name "shares")) {
$candidateName = [string](Get-ObjectPropertyValue -Object $shareConfig -Name "name")
if ([string]::IsNullOrWhiteSpace($candidateName)) {
$candidateName = [string](Get-ObjectPropertyValue -Object $shareConfig -Name "shareName")
}

$candidateUnc = [string](Get-ObjectPropertyValue -Object $shareConfig -Name "uncPath")

if (-not [string]::IsNullOrWhiteSpace($candidateName) -and
[string]::Equals($candidateName, $shareName, [System.StringComparison]::OrdinalIgnoreCase)) {
return $shareConfig
}

if (-not [string]::IsNullOrWhiteSpace($candidateUnc) -and
[string]::Equals($candidateUnc, $uncPath, [System.StringComparison]::OrdinalIgnoreCase)) {
return $shareConfig
}
}

return $null
}

function Set-ShareScanConfiguration {
param(
[object[]]$Shares,
[object]$Config,
[int]$CommandLineAclDepth,
[string]$CurrentServer
)

$defaultScanDepth = Convert-AclDepthToScanDepth -AclDepth $CommandLineAclDepth
$defaultSource = "CommandLine"

if ($null -ne $Config) {
$configDefaultDepth = Get-OptionalIntProperty -Object $Config -Name "defaultAclDepth"
if ($null -eq $configDefaultDepth) {
$configDefaultDepth = Get-OptionalIntProperty -Object $Config -Name "defaultScanDepth"
}

if ($null -ne $configDefaultDepth) {
$defaultScanDepth = [int]$configDefaultDepth
$defaultSource = "ConfigDefault"
}
}

$targetConfig = Find-TargetConfig -Config $Config -ServerName $CurrentServer
$targetScanDepth = $null
if ($null -ne $targetConfig) {
$targetScanDepth = Get-OptionalIntProperty -Object $targetConfig -Name "scanDepth"
}

foreach ($share in @($Shares)) {
$scanDepth = $defaultScanDepth
$source = $defaultSource

if ($null -ne $targetScanDepth) {
$scanDepth = [int]$targetScanDepth
$source = "Target"
}

$shareConfig = Find-ShareConfig -TargetConfig $targetConfig -Share $share
if ($null -ne $shareConfig) {
$shareScanDepth = Get-OptionalIntProperty -Object $shareConfig -Name "scanDepth"
if ($null -ne $shareScanDepth) {
$scanDepth = [int]$shareScanDepth
$source = "Share"
}
}

$effectiveAclDepth = Convert-ScanDepthToAclDepth -ScanDepth $scanDepth

$share | Add-Member -NotePropertyName ConfiguredScanDepth -NotePropertyValue $scanDepth -Force
$share | Add-Member -NotePropertyName EffectiveAclDepth -NotePropertyValue $effectiveAclDepth -Force
$share | Add-Member -NotePropertyName ScanDepthSource -NotePropertyValue $source -Force
}

return $Shares
}

function New-ScanConfigFromShares {
param(
[object[]]$Shares,
[object]$ExistingConfig,
[int]$DefaultScanDepth,
[string]$Path
)

$serverValues = New-Object System.Collections.Generic.List[string]

foreach ($share in @($Shares)) {
if ($null -ne $share -and -not [string]::IsNullOrWhiteSpace([string]$share.Server)) {
$serverValues.Add([string]$share.Server)
}
}

foreach ($target in @(Get-ConfigArrayProperty -Object $ExistingConfig -Name "targets")) {
$targetServer = [string](Get-ObjectPropertyValue -Object $target -Name "server")
if (-not [string]::IsNullOrWhiteSpace($targetServer)) {
$serverValues.Add($targetServer)
}
}

$servers = @($serverValues.ToArray() | Sort-Object -Unique)
$targets = New-Object System.Collections.Generic.List[object]

foreach ($serverName in $servers) {
$targetConfig = Find-TargetConfig -Config $ExistingConfig -ServerName $serverName
$targetDepth = Get-OptionalIntProperty -Object $targetConfig -Name "scanDepth"
if ($null -eq $targetDepth) { $targetDepth = $DefaultScanDepth }

$shareValues = New-Object System.Collections.Generic.List[object]
$shareRows = @($Shares | Where-Object { [string]::Equals([string]$_.Server, $serverName, [System.StringComparison]::OrdinalIgnoreCase) } | Sort-Object ShareName)

foreach ($share in $shareRows) {
$shareDepth = $DefaultScanDepth
if ($null -ne $share.PSObject.Properties["ConfiguredScanDepth"] -and $null -ne $share.ConfiguredScanDepth) {
$shareDepth = [int]$share.ConfiguredScanDepth
}

$shareValues.Add([ordered]@{
name = [string]$share.ShareName
uncPath = [string]$share.UNCPath
scanDepth = $shareDepth
})
}

foreach ($existingShare in @(Get-ConfigArrayProperty -Object $targetConfig -Name "shares")) {
$existingName = [string](Get-ObjectPropertyValue -Object $existingShare -Name "name")
if ([string]::IsNullOrWhiteSpace($existingName)) {
$existingName = [string](Get-ObjectPropertyValue -Object $existingShare -Name "shareName")
}
if ([string]::IsNullOrWhiteSpace($existingName)) { continue }

$alreadyPresent = $false
foreach ($row in $shareValues) {
$currentName = [string](Get-ObjectPropertyValue -Object $row -Name "name")
if ([string]::Equals($currentName, $existingName, [System.StringComparison]::OrdinalIgnoreCase)) {
$alreadyPresent = $true
break
}
}
if ($alreadyPresent) { continue }

$existingDepth = Get-OptionalIntProperty -Object $existingShare -Name "scanDepth"
if ($null -eq $existingDepth) { $existingDepth = $targetDepth }

$shareValues.Add([ordered]@{
name = $existingName
uncPath = [string](Get-ObjectPropertyValue -Object $existingShare -Name "uncPath")
scanDepth = [int]$existingDepth
})
}

$targets.Add([ordered]@{
server = $serverName
scanDepth = [int]$targetDepth
shares = @($shareValues.ToArray())
})
}

$domain = Get-ObjectPropertyValue -Object $ExistingConfig -Name "domain"
if ($null -eq $domain) {
$domain = [ordered]@{
enabled = $true
domainName = ""
preferredDomainController = ""
resolveNestedGroups = $true
maxNestedGroupDepth = 5
cacheIdentityLookups = $true
}
}

return [ordered]@{
version = 1
depthCounting = "Server=1;Share=2;FirstFolder=3"
defaultAclDepth = $DefaultScanDepth
configPath = $Path
domain = $domain
subnets = @(Get-ConfigArrayProperty -Object $ExistingConfig -Name "subnets")
targets = @($targets.ToArray())
}
}

function Add-ListRows {
param(
[System.Collections.Generic.List[object]]$Target,
[object[]]$Rows
)

foreach ($row in @($Rows)) {
if ($null -ne $row) {
$Target.Add($row)
}
}
}

function Copy-DataJsonToCentral {
param(
[string]$JsonPath,
[string]$DestinationPath,
[string]$ServerName,
[string]$CurrentRunId,
[switch]$KeepHistory
)

if ([string]::IsNullOrWhiteSpace($DestinationPath)) { return $null }

try {
New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null

$safeServer = $ServerName
if ([string]::IsNullOrWhiteSpace($safeServer)) { $safeServer = "UnknownServer" }
$safeServer = $safeServer -replace '[^A-Za-z0-9_.-]', '_'

if ($KeepHistory) {
$destinationFile = Join-Path $DestinationPath ("data_{0}_{1}.json" -f $safeServer, $CurrentRunId)
}
else {
$destinationFile = Join-Path $DestinationPath ("data_{0}.json" -f $safeServer)
}
Copy-Item -LiteralPath $JsonPath -Destination $destinationFile -Force
return $destinationFile
}
catch {
Write-Log "Could not copy data.json to central folder $DestinationPath. Error: $($_.Exception.Message)" "WARN"
return $null
}
}

function Get-CentralDashboardData {
param([string]$JsonFolder)

$summaryRows = New-Object System.Collections.Generic.List[object]
$shareRows = New-Object System.Collections.Generic.List[object]
$sharePermissionRows = New-Object System.Collections.Generic.List[object]
$ntfsAclRows = New-Object System.Collections.Generic.List[object]
$accessDiagnosticRows = New-Object System.Collections.Generic.List[object]
$riskRows = New-Object System.Collections.Generic.List[object]
$userAccessRows = New-Object System.Collections.Generic.List[object]
$robocopyRows = New-Object System.Collections.Generic.List[object]
$sourceFiles = New-Object System.Collections.Generic.List[object]

$jsonFiles = @(Get-ChildItem -LiteralPath $JsonFolder -Filter "*.json" -Recurse -ErrorAction Stop |
Where-Object { -not $_.PSIsContainer -and $_.Name -ne "targets.json" })

foreach ($file in $jsonFiles) {
try {
$raw = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
$data = $raw | ConvertFrom-Json
$meta = Get-ObjectPropertyValue -Object $data -Name "meta"
if ($null -eq $meta) {
continue
}
$scope = [string](Get-ObjectPropertyValue -Object $meta -Name "scope")

if ($scope -eq "CentralDashboard") {
continue
}

Add-ListRows -Target $summaryRows -Rows (Get-JsonArrayProperty -Object $data -Name "summary")
$shares = @(Get-JsonArrayProperty -Object $data -Name "shares")
$sharePermissions = @(Get-JsonArrayProperty -Object $data -Name "sharePermissions")
$ntfsAcls = @(Get-JsonArrayProperty -Object $data -Name "ntfsAcls")

Add-ListRows -Target $shareRows -Rows $shares
Add-ListRows -Target $sharePermissionRows -Rows $sharePermissions
Add-ListRows -Target $ntfsAclRows -Rows $ntfsAcls
Add-ListRows -Target $accessDiagnosticRows -Rows (Get-JsonArrayProperty -Object $data -Name "accessDiagnostics")
Add-ListRows -Target $riskRows -Rows (Get-JsonArrayProperty -Object $data -Name "risk")
Add-ListRows -Target $robocopyRows -Rows (Get-JsonArrayProperty -Object $data -Name "robocopyPlan")

$existingUserAccess = @(Get-JsonArrayProperty -Object $data -Name "userAccess")
if ($existingUserAccess.Count -gt 0) {
Add-ListRows -Target $userAccessRows -Rows $existingUserAccess
}
else {
Add-ListRows -Target $userAccessRows -Rows (Get-UserAccessRows -Shares $shares -SharePermissions $sharePermissions -NtfsAcls $ntfsAcls)
}

$sourceFiles.Add([pscustomobject]@{
FileName = $file.Name
FullName = $file.FullName
Server = [string](Get-ObjectPropertyValue -Object $meta -Name "server")
RunId = [string](Get-ObjectPropertyValue -Object $meta -Name "runId")
GeneratedAt = [string](Get-ObjectPropertyValue -Object $meta -Name "generatedAt")
})
}
catch {
Write-Log "Skipping unreadable JSON file $($file.FullName). Error: $($_.Exception.Message)" "WARN"
}
}

$serverValues = New-Object System.Collections.Generic.List[string]

foreach ($row in $shareRows) {
if ($null -ne $row -and -not [string]::IsNullOrWhiteSpace([string]$row.Server)) {
$serverValues.Add([string]$row.Server)
}
}

foreach ($row in $summaryRows) {
if ($null -ne $row -and -not [string]::IsNullOrWhiteSpace([string]$row.Server)) {
$serverValues.Add([string]$row.Server)
}
}

$servers = @($serverValues.ToArray() | Sort-Object -Unique)

$serverLabel = "Multiple servers"
if ($servers.Count -eq 1) {
$serverLabel = [string]$servers[0]
}
elseif ($servers.Count -gt 1) {
$serverLabel = "Multiple servers ({0})" -f $servers.Count
}

$centralDefaultScanDepth = 5
foreach ($row in $summaryRows) {
$summaryDepth = Get-OptionalIntProperty -Object $row -Name "DefaultScanDepth"
if ($null -ne $summaryDepth) {
$centralDefaultScanDepth = [int]$summaryDepth
break
}
}

$centralScanConfig = New-ScanConfigFromShares -Shares ($shareRows.ToArray()) -ExistingConfig $null -DefaultScanDepth $centralDefaultScanDepth -Path ""

return [ordered]@{
meta = [ordered]@{
scope = "CentralDashboard"
runId = "Central_$RunId"
server = $serverLabel
generatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
outputPath = $JsonFolder
centralJsonPath = $JsonFolder
configDefaultScanDepth = $centralDefaultScanDepth
sourceJsonFiles = $sourceFiles.Count
servers = $servers
}
summary = @(Convert-ForJson ($summaryRows.ToArray()))
shares = @(Convert-ForJson ($shareRows.ToArray()))
sharePermissions = @(Convert-ForJson ($sharePermissionRows.ToArray()))
ntfsAcls = @(Convert-ForJson ($ntfsAclRows.ToArray()))
accessDiagnostics = @(Convert-ForJson ($accessDiagnosticRows.ToArray()))
risk = @(Convert-ForJson ($riskRows.ToArray()))
userAccess = @(Convert-ForJson ($userAccessRows.ToArray()))
robocopyPlan = @(Convert-ForJson ($robocopyRows.ToArray()))
sourceFiles = @(Convert-ForJson ($sourceFiles.ToArray()))
scanConfig = $centralScanConfig
}
}

function Export-DashboardCsvFiles {
param([object]$Data)

Export-CsvSafe -Data @(Get-JsonArrayProperty -Object $Data -Name "summary") -Name "Summary.csv" | Out-Null
Export-CsvSafe -Data @(Get-JsonArrayProperty -Object $Data -Name "shares") -Name "SMB_Shares.csv" | Out-Null
Export-CsvSafe -Data @(Get-JsonArrayProperty -Object $Data -Name "sharePermissions") -Name "SMB_Share_Permissions.csv" | Out-Null
Export-CsvSafe -Data @(Get-JsonArrayProperty -Object $Data -Name "ntfsAcls") -Name "NTFS_ACLs.csv" | Out-Null
Export-CsvSafe -Data @(Get-JsonArrayProperty -Object $Data -Name "accessDiagnostics") -Name "Access_Diagnostics.csv" | Out-Null
Export-CsvSafe -Data @(Get-JsonArrayProperty -Object $Data -Name "risk") -Name "Migration_Risk_Assessment.csv" | Out-Null
Export-CsvSafe -Data @(Get-JsonArrayProperty -Object $Data -Name "userAccess") -Name "User_Access.csv" | Out-Null
Export-CsvSafe -Data @(Get-JsonArrayProperty -Object $Data -Name "robocopyPlan") -Name "Robocopy_Migration_Plan.csv" | Out-Null
}

function ConvertTo-DashboardSafeString {
param([AllowNull()][string]$Value)

if ($null -eq $Value) { return $null }

$builder = New-Object System.Text.StringBuilder
foreach ($ch in $Value.ToCharArray()) {
$code = [int][char]$ch
if ($code -lt 32) {
[void]$builder.Append(" ")
}
else {
[void]$builder.Append($ch)
}
}

return $builder.ToString()
}

function ConvertTo-DashboardSafeObject {
param([object]$Value)

if ($null -eq $Value) { return $null }
if ($Value -is [string]) { return ConvertTo-DashboardSafeString -Value $Value }
if ($Value -is [System.ValueType]) { return $Value }

if ($Value -is [System.Collections.IDictionary]) {
$hash = [ordered]@{}
foreach ($key in $Value.Keys) {
$hash[$key] = ConvertTo-DashboardSafeObject -Value $Value[$key]
}
return $hash
}

if ($Value -is [System.Collections.IEnumerable]) {
$items = New-Object System.Collections.Generic.List[object]
foreach ($item in $Value) {
$items.Add((ConvertTo-DashboardSafeObject -Value $item))
}
return ,@($items.ToArray())
}

$object = [ordered]@{}
foreach ($property in $Value.PSObject.Properties) {
try {
$object[$property.Name] = ConvertTo-DashboardSafeObject -Value $property.Value
}
catch {
$object[$property.Name] = $null
}
}
return $object
}

function ConvertTo-DashboardJson {
param([object]$Data)

$safeData = ConvertTo-DashboardSafeObject -Value $Data
return ($safeData | ConvertTo-Json -Depth 12 -Compress)
}

function Write-DashboardHtmlFile {
param(
[string]$HtmlPath,
[string]$Json
)

New-DashboardHtml -HtmlPath $HtmlPath

# Embed Base64 JSON so file:// dashboards are not broken by raw control characters or HTML parsing.
$htmlContent = Get-Content -LiteralPath $HtmlPath -Raw -Encoding UTF8
$jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($Json)
$encodedJson = [Convert]::ToBase64String($jsonBytes)
$htmlContent = $htmlContent.Replace("__FST_DATA_PLACEHOLDER__", $encodedJson)
Set-Content -LiteralPath $HtmlPath -Value $htmlContent -Encoding UTF8
}

function Publish-GitHubPagesDashboard {
param(
[string]$PagesPath,
[string]$Json
)

if ([string]::IsNullOrWhiteSpace($PagesPath)) { return $null }

try {
New-Item -ItemType Directory -Path $PagesPath -Force | Out-Null
$indexPath = Join-Path $PagesPath "index.html"
Write-DashboardHtmlFile -HtmlPath $indexPath -Json $Json
Set-Content -Path (Join-Path $PagesPath ".nojekyll") -Value "" -Encoding ASCII
return $indexPath
}
catch {
Write-Log "Could not publish GitHub Pages dashboard to $PagesPath. Error: $($_.Exception.Message)" "WARN"
return $null
}
}

function New-CentralDashboardCommand {
param(
[string]$CommandPath,
[string]$DashboardFileName,
[string]$JsonFolder,
[string]$SourceScriptPath
)

try {
$commandFolder = Split-Path -Path $CommandPath -Parent
$scriptFileName = "Invoke-FileShareToolkit_Portable_v3_2.ps1"

if (-not [string]::IsNullOrWhiteSpace($SourceScriptPath) -and (Test-Path -LiteralPath $SourceScriptPath)) {
$scriptFileName = Split-Path -Path $SourceScriptPath -Leaf
$scriptDestination = Join-Path $commandFolder $scriptFileName

if (-not [string]::Equals($SourceScriptPath, $scriptDestination, [System.StringComparison]::OrdinalIgnoreCase)) {
Copy-Item -LiteralPath $SourceScriptPath -Destination $scriptDestination -Force
}
}

$cmd = @"
@echo off
setlocal
set "FST_DIR=%~dp0"
set "FST_JSON=$JsonFolder"
set "FST_SCRIPT=%FST_DIR%$scriptFileName"
set "FST_DASHBOARD=%FST_DIR%$DashboardFileName"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%FST_SCRIPT%" -GenerateCentralDashboard -CentralJsonPath "%FST_JSON%" -CentralDashboardPath "%FST_DASHBOARD%" -OpenDashboard
if errorlevel 1 (
  echo.
  echo Central dashboard generation failed.
  pause
  exit /b %errorlevel%
)

echo.
echo Central dashboard updated: "%FST_DASHBOARD%"
"@

Set-Content -Path $CommandPath -Value $cmd -Encoding ASCII
return $CommandPath
}
catch {
Write-Log "Could not create central dashboard command file $CommandPath. Error: $($_.Exception.Message)" "WARN"
return $null
}
}

function Resolve-ConfigFilePath {
param(
[string]$Path,
[string]$SourceScriptPath
)

if (-not [string]::IsNullOrWhiteSpace($Path)) {
try {
return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}
catch {
try {
return [System.IO.Path]::GetFullPath($Path)
}
catch {
return $Path
}
}
}

$scriptFolder = $null
if (-not [string]::IsNullOrWhiteSpace($SourceScriptPath)) {
$scriptFolder = Split-Path -Path $SourceScriptPath -Parent
}
if ([string]::IsNullOrWhiteSpace($scriptFolder)) {
$scriptFolder = (Get-Location).Path
}

return (Join-Path (Join-Path $scriptFolder "config") "targets.json")
}

function New-ConfigSaveServerFiles {
param(
[string]$OutputFolder,
[string]$TargetConfigPath,
[int]$Port
)

try {
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null

$serverScriptPath = Join-Path $OutputFolder "ConfigSaveServer.ps1"
$commandPath = Join-Path $OutputFolder "Start-ConfigSaveServer.cmd"
$targetLiteral = $TargetConfigPath -replace "'", "''"

$serverScript = @'
$ErrorActionPreference = "Stop"

$Port = __PORT__
$TargetConfigPath = '__TARGET_CONFIG_PATH__'

function Write-JsonResponse {
param(
[System.Net.HttpListenerResponse]$Response,
[int]$StatusCode,
[string]$Json
)

$Response.StatusCode = $StatusCode
$Response.ContentType = "application/json; charset=utf-8"
$Response.Headers["Access-Control-Allow-Origin"] = "*"
$Response.Headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
$Response.Headers["Access-Control-Allow-Headers"] = "Content-Type"
$Response.Headers["Access-Control-Allow-Private-Network"] = "true"

$bytes = [System.Text.Encoding]::UTF8.GetBytes($Json)
$Response.ContentLength64 = $bytes.Length
$Response.OutputStream.Write($bytes, 0, $bytes.Length)
$Response.OutputStream.Close()
}

function Ensure-Folder {
param([string]$Path)

if ([string]::IsNullOrWhiteSpace($Path)) { return }
if (-not (Test-Path -LiteralPath $Path)) {
New-Item -ItemType Directory -Path $Path -Force | Out-Null
}
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add(("http://127.0.0.1:{0}/" -f $Port))
$listener.Start()

Write-Host ("FileShareToolkit config save server listening on http://127.0.0.1:{0}/" -f $Port)
Write-Host ("Writing config to: {0}" -f $TargetConfigPath)
Write-Host "Close this window to stop the save server."

while ($listener.IsListening) {
$context = $listener.GetContext()
$request = $context.Request
$response = $context.Response

try {
$response.Headers["Access-Control-Allow-Origin"] = "*"
$response.Headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
$response.Headers["Access-Control-Allow-Headers"] = "Content-Type"
$response.Headers["Access-Control-Allow-Private-Network"] = "true"

if ($request.HttpMethod -eq "OPTIONS") {
$response.StatusCode = 204
$response.Close()
continue
}

if ($request.HttpMethod -eq "GET" -and $request.Url.AbsolutePath -eq "/health") {
Write-JsonResponse -Response $response -StatusCode 200 -Json ('{"ok":true,"path":"' + ($TargetConfigPath.Replace('\','\\').Replace('"','\"')) + '"}')
continue
}

if ($request.HttpMethod -eq "POST" -and $request.Url.AbsolutePath -eq "/save-config") {
$reader = New-Object System.IO.StreamReader($request.InputStream, $request.ContentEncoding)
$body = $reader.ReadToEnd()
$reader.Close()

if ([string]::IsNullOrWhiteSpace($body)) {
Write-JsonResponse -Response $response -StatusCode 400 -Json '{"ok":false,"error":"Empty request body."}'
continue
}

try {
$body | ConvertFrom-Json | Out-Null
}
catch {
Write-JsonResponse -Response $response -StatusCode 400 -Json ('{"ok":false,"error":"Invalid JSON: ' + ($_.Exception.Message.Replace('\','\\').Replace('"','\"')) + '"}')
continue
}

$targetFolder = Split-Path -Path $TargetConfigPath -Parent
Ensure-Folder -Path $targetFolder

if (Test-Path -LiteralPath $TargetConfigPath) {
$backupPath = "{0}.bak_{1}" -f $TargetConfigPath, (Get-Date -Format "yyyyMMdd_HHmmss")
Copy-Item -LiteralPath $TargetConfigPath -Destination $backupPath -Force
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($TargetConfigPath, $body, $utf8NoBom)

Write-JsonResponse -Response $response -StatusCode 200 -Json ('{"ok":true,"path":"' + ($TargetConfigPath.Replace('\','\\').Replace('"','\"')) + '"}')
continue
}

Write-JsonResponse -Response $response -StatusCode 404 -Json '{"ok":false,"error":"Unknown endpoint."}'
}
catch {
try {
Write-JsonResponse -Response $response -StatusCode 500 -Json ('{"ok":false,"error":"' + ($_.Exception.Message.Replace('\','\\').Replace('"','\"')) + '"}')
}
catch {
$response.Close()
}
}
}
'@

$serverScript = $serverScript.Replace("__PORT__", [string]$Port).Replace("__TARGET_CONFIG_PATH__", $targetLiteral)
Set-Content -Path $serverScriptPath -Value $serverScript -Encoding UTF8

$cmd = @"
@echo off
setlocal
set "FST_DIR=%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%FST_DIR%ConfigSaveServer.ps1"
"@

Set-Content -Path $commandPath -Value $cmd -Encoding ASCII

return [pscustomobject]@{
ServerScriptPath = $serverScriptPath
CommandPath = $commandPath
CommandFileName = (Split-Path -Path $commandPath -Leaf)
Endpoint = ("http://127.0.0.1:{0}/save-config" -f $Port)
TargetConfigPath = $TargetConfigPath
Port = $Port
}
}
catch {
Write-Log "Could not create config save server files in $OutputFolder. Error: $($_.Exception.Message)" "WARN"
return $null
}
}

function Start-ConfigSaveServerProcess {
param([string]$ServerScriptPath)

if ([string]::IsNullOrWhiteSpace($ServerScriptPath)) { return }

try {
Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile","-ExecutionPolicy","Bypass","-File",$ServerScriptPath) -WindowStyle Minimized | Out-Null
Write-Log "Started local config save server: $ServerScriptPath"
}
catch {
Write-Log "Could not start local config save server. Use Start-ConfigSaveServer.cmd from the dashboard folder. Error: $($_.Exception.Message)" "WARN"
}
}

if ($GenerateCentralDashboard) {
Write-Log "Generating central FileShareToolkit dashboard from $CentralJsonPath"

if ([string]::IsNullOrWhiteSpace($CentralDashboardPath)) {
$CentralDashboardPath = Join-Path $CentralJsonPath "CentralDashboard.html"
}

$centralDashboardFileName = Split-Path -Path $CentralDashboardPath -Leaf
$centralDashboardFolder = Split-Path -Path $CentralDashboardPath -Parent
if ([string]::IsNullOrWhiteSpace($centralDashboardFolder)) {
$centralDashboardFolder = $CentralJsonPath
}
New-Item -ItemType Directory -Path $centralDashboardFolder -Force | Out-Null

$centralCommandFileName = "Generate-CentralDashboard.cmd"
$centralCommandPath = Join-Path $centralDashboardFolder $centralCommandFileName
$createdCommandPath = New-CentralDashboardCommand -CommandPath $centralCommandPath -DashboardFileName $centralDashboardFileName -JsonFolder $CentralJsonPath -SourceScriptPath $ScriptPath
$centralConfigTargetPath = Resolve-ConfigFilePath -Path $ConfigPath -SourceScriptPath $ScriptPath
$centralConfigSaveServer = New-ConfigSaveServerFiles -OutputFolder $centralDashboardFolder -TargetConfigPath $centralConfigTargetPath -Port (Get-Random -Minimum 17800 -Maximum 18100)

$centralData = Get-CentralDashboardData -JsonFolder $CentralJsonPath
$centralData.meta["scriptFileName"] = (Split-Path -Path $ScriptPath -Leaf)
$centralData.meta["scriptPath"] = $ScriptPath
$centralData.meta["exportCsvFiles"] = [bool]$ExportCsvFiles
if (-not [string]::IsNullOrWhiteSpace($createdCommandPath)) {
$centralData.meta["generateCentralDashboardCommand"] = $centralCommandFileName
}
if ($null -ne $centralConfigSaveServer) {
$centralData.meta["localConfigSaveEndpoint"] = $centralConfigSaveServer.Endpoint
$centralData.meta["localConfigSaveServerCommand"] = $centralConfigSaveServer.CommandFileName
$centralData.meta["configTargetPath"] = $centralConfigSaveServer.TargetConfigPath
}
$centralJson = ConvertTo-DashboardJson -Data $centralData
$centralJsonPath = Join-Path $CentralJsonPath "data.json"
$centralJson | Set-Content -Path $centralJsonPath -Encoding UTF8

if ($ExportCsvFiles) {
Export-DashboardCsvFiles -Data $centralData
}
Write-DashboardHtmlFile -HtmlPath $CentralDashboardPath -Json $centralJson
$pagesDashboardPath = Publish-GitHubPagesDashboard -PagesPath $GitHubPagesPath -Json $centralJson

Write-Log "Completed central dashboard."
Write-Log "Central dashboard: $CentralDashboardPath"
if (-not [string]::IsNullOrWhiteSpace($pagesDashboardPath)) {
Write-Log "GitHub Pages dashboard: $pagesDashboardPath"
}
Write-Log "Central data JSON: $centralJsonPath"
if (-not [string]::IsNullOrWhiteSpace($createdCommandPath)) {
Write-Log "Central dashboard button command: $createdCommandPath"
}
if ($null -ne $centralConfigSaveServer) {
Write-Log "Config save endpoint: $($centralConfigSaveServer.Endpoint)"
Write-Log "Config target path: $($centralConfigSaveServer.TargetConfigPath)"
}

if ($OpenDashboard) {
if ($null -ne $centralConfigSaveServer) {
Start-ConfigSaveServerProcess -ServerScriptPath $centralConfigSaveServer.ServerScriptPath
}
Start-Process $CentralDashboardPath
}

return
}

Write-Log "Starting FileShareToolkit Portable v3.2 on $Server"
Write-Log "Output folder: $RunRoot"
Write-Log "MaxAclDepth: $MaxAclDepth"
Write-Log "TargetServer: $TargetServer"
Write-Log "ExportCsvFiles: $ExportCsvFiles"
Write-Log "SkipAccessDiagnostics: $SkipAccessDiagnostics"
Write-Log "MaxAccessDiagnosticGroups: $MaxAccessDiagnosticGroups"
Write-Log "MaxDiagnosticFileSamplesPerFolder: $MaxDiagnosticFileSamplesPerFolder"
if (-not [string]::IsNullOrWhiteSpace($RobocopyDiagnosticDestinationRoot)) {
Write-Log "RobocopyDiagnosticDestinationRoot: $RobocopyDiagnosticDestinationRoot"
}
if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
Write-Log "ConfigPath: $ConfigPath"
}

$toolkitConfig = Read-ToolkitConfig -Path $ConfigPath
$configDefaultScanDepth = Convert-AclDepthToScanDepth -AclDepth $MaxAclDepth
if ($null -ne $toolkitConfig) {
$configuredDefaultDepth = Get-OptionalIntProperty -Object $toolkitConfig -Name "defaultAclDepth"
if ($null -eq $configuredDefaultDepth) {
$configuredDefaultDepth = Get-OptionalIntProperty -Object $toolkitConfig -Name "defaultScanDepth"
}
if ($null -ne $configuredDefaultDepth) {
$configDefaultScanDepth = [int]$configuredDefaultDepth
}
}

$shares = Get-LocalShares
$shares = Set-ShareScanConfiguration -Shares @($shares) -Config $toolkitConfig -CommandLineAclDepth $MaxAclDepth -CurrentServer $Server
$sharePermissions = @()
if (-not $SkipSharePermissions) {
$sharePermissions = Get-SharePermissions -Shares @($shares)
}
$ntfsAcls = Get-NtfsAclRows -Shares @($shares) -Depth $MaxAclDepth
$accessDiagnostics = @()
if (-not $SkipAccessDiagnostics) {
$failedAclCount = @($ntfsAcls | Where-Object { $_.ScanStatus -eq "Failed" }).Count
if ($failedAclCount -gt 0) {
Write-Log "Generating access diagnostics for $failedAclCount failed ACL rows."
$accessDiagnostics = Get-AccessDiagnosticRows -NtfsAcls @($ntfsAcls) -DestinationRoot $RobocopyDiagnosticDestinationRoot -MaxGroups $MaxAccessDiagnosticGroups -MaxFileSamplesPerFolder $MaxDiagnosticFileSamplesPerFolder
}
else {
Write-Log "No failed ACL rows found; access diagnostics are not needed."
}
}
else {
Write-Log "Access diagnostics skipped by -SkipAccessDiagnostics."
}
$risk = Get-RiskAssessment -Shares @($shares) -SharePermissions @($sharePermissions) -NtfsAcls @($ntfsAcls)
$robocopyPlan = Get-RobocopyPlan -Shares @($shares) -Target $TargetServer -Threads $RobocopyThreads
$userAccess = Get-UserAccessRows -Shares @($shares) -SharePermissions @($sharePermissions) -NtfsAcls @($ntfsAcls)
$scanConfig = New-ScanConfigFromShares -Shares @($shares) -ExistingConfig $toolkitConfig -DefaultScanDepth $configDefaultScanDepth -Path $ConfigPath

$summary = [pscustomobject]@{
RunId = $RunId
Server = $Server
GeneratedAt = Get-Date
OutputPath = $RunRoot
MaxAclDepth = $MaxAclDepth
DefaultScanDepth = $configDefaultScanDepth
ConfigPath = $ConfigPath
TargetServer = $TargetServer
Shares = @($shares).Count
SharePermissionRows = @($sharePermissions).Count
NtfsAclRows = @($ntfsAcls).Count
FailedAclRows = @($ntfsAcls | Where-Object { $_.ScanStatus -eq "Failed" }).Count
AccessDiagnosticRows = @($accessDiagnostics).Count
RiskRows = @($risk).Count
RobocopyRows = @($robocopyPlan).Count
UserAccessRows = @($userAccess).Count
}

if ($ExportCsvFiles) {
Export-CsvSafe -Data @($summary) -Name "Summary.csv" | Out-Null
Export-CsvSafe -Data @($shares) -Name "SMB_Shares.csv" | Out-Null
Export-CsvSafe -Data @($sharePermissions) -Name "SMB_Share_Permissions.csv" | Out-Null
Export-CsvSafe -Data @($ntfsAcls) -Name "NTFS_ACLs.csv" | Out-Null
Export-CsvSafe -Data @($accessDiagnostics) -Name "Access_Diagnostics.csv" | Out-Null
Export-CsvSafe -Data @($risk) -Name "Migration_Risk_Assessment.csv" | Out-Null
Export-CsvSafe -Data @($userAccess) -Name "User_Access.csv" | Out-Null
Export-CsvSafe -Data @($robocopyPlan) -Name "Robocopy_Migration_Plan.csv" | Out-Null
}

$data = [ordered]@{
meta = [ordered]@{
runId = $RunId
server = $Server
generatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
outputPath = $RunRoot
maxAclDepth = $MaxAclDepth
configDefaultScanDepth = $configDefaultScanDepth
configPath = $ConfigPath
centralJsonPath = $CentralJsonPath
targetServer = $TargetServer
robocopyDiagnosticDestinationRoot = $RobocopyDiagnosticDestinationRoot
skipAccessDiagnostics = [bool]$SkipAccessDiagnostics
maxAccessDiagnosticGroups = $MaxAccessDiagnosticGroups
maxDiagnosticFileSamplesPerFolder = $MaxDiagnosticFileSamplesPerFolder
scriptFileName = (Split-Path -Path $ScriptPath -Leaf)
scriptPath = $ScriptPath
exportCsvFiles = [bool]$ExportCsvFiles
}
summary = @(Convert-ForJson @($summary))
shares = @(Convert-ForJson @($shares))
sharePermissions = @(Convert-ForJson @($sharePermissions))
ntfsAcls = @(Convert-ForJson @($ntfsAcls))
accessDiagnostics = @(Convert-ForJson @($accessDiagnostics))
risk = @(Convert-ForJson @($risk))
userAccess = @(Convert-ForJson @($userAccess))
robocopyPlan = @(Convert-ForJson @($robocopyPlan))
scanConfig = $scanConfig
}

$configTargetPath = Resolve-ConfigFilePath -Path $ConfigPath -SourceScriptPath $ScriptPath
$configSaveServer = New-ConfigSaveServerFiles -OutputFolder $RunRoot -TargetConfigPath $configTargetPath -Port (Get-Random -Minimum 17800 -Maximum 18100)
if ($null -ne $configSaveServer) {
$data.meta["localConfigSaveEndpoint"] = $configSaveServer.Endpoint
$data.meta["localConfigSaveServerCommand"] = $configSaveServer.CommandFileName
$data.meta["configTargetPath"] = $configSaveServer.TargetConfigPath
}

$jsonPath = Join-Path $RunRoot "data.json"
$json = ConvertTo-DashboardJson -Data $data
$json | Set-Content -Path $jsonPath -Encoding UTF8

$centralCopyPath = Copy-DataJsonToCentral -JsonPath $jsonPath -DestinationPath $CentralJsonPath -ServerName $Server -CurrentRunId $RunId -KeepHistory:$KeepCentralRunHistory
if (-not [string]::IsNullOrWhiteSpace($centralCopyPath)) {
Write-Log "Copied data JSON to central folder: $centralCopyPath"
}

$htmlPath = Join-Path $RunRoot "Dashboard.html"
Write-DashboardHtmlFile -HtmlPath $htmlPath -Json $json

Write-Log "Completed."
Write-Log "Dashboard: $htmlPath"
Write-Log "Data JSON: $jsonPath"
if ($null -ne $configSaveServer) {
Write-Log "Config save endpoint: $($configSaveServer.Endpoint)"
Write-Log "Config target path: $($configSaveServer.TargetConfigPath)"
}

$summary | Format-List

if ($OpenDashboard) {
if ($null -ne $configSaveServer) {
Start-ConfigSaveServerProcess -ServerScriptPath $configSaveServer.ServerScriptPath
}
Start-Process $htmlPath
}
