# Resilient v1.6.13 RC18c (PS 5.1-safe)
# Unified Vulnerability Management Automation Framework
# ----------------------------------------------------------------------------------
# RC18c: Fixes + small perf/reliability tweaks over RC18b
# - Fix: Create-FamilyScopeIfMissing param list stray ']' causing parse error.
# - Fix: Parallel validation runspace bootstrap now includes STrim and Add-Audit.
# - Robust Add-Audit: auto-initialize $script:Audit if missing (safe for runspaces).
# - Reliability: Ensure TLS 1.2 before Install-Module on PS 5.1; harden error actions.
# - Perf: Default Export-Excel -NoNumberConversion via $PSDefaultParameterValues.
# - Kept RC18b optimizations (caches, column projection, parallel validations, etc.).
# ----------------------------------------------------------------------------------
# REQUIREMENTS: Windows PowerShell 5.1, .NET 4.8, ImportExcel module

#Requires -Version 5.1

param(
    # Week column uses year to avoid header collisions across years
    [string]$WeekDate = (Get-Date -Format "M/d/yy"),
    [switch]$SkipValidation,
    [switch]$GenerateDashboard,
    [string[]]$ReportTypes = @("Workstations", "MS Servers", "Non-MS Servers"),

    # Performance/UX
    [switch]$FastMode,
    [switch]$NoProgress,
    [switch]$SkipFormatting,
    [int]$ValidationMaxFiles = 0,

    # Optional behavior
    [switch]$CreateMissingScopes,
    [switch]$ForceReprocess
)

# ================================================================================
# CONFIG
# ==============================================================================
$Config = @{
    BasePath    = "C:\Lumen21"
    Performance = @{
        EnableAutoSize     = $false
        FastModeDefault    = $true
        ValidationParallel = $true      # enable parallel validations (requires SSD recommended)
        ValidationDegree   = 3          # max parallel validations (2–3 is sensible)
    }
    Tenable     = @{ KeepLatestCopy = $true; LatestCopyPath = "" }
    Quality     = @{
        CriticalFieldMissingThresholdPercent = 10
        PreferSheetLastSeen                  = $false
        GateCompletedByValidation            = $false
        AmbiguityLogLimit                    = 50
        LogCustomColumnWarn                  = $false   # set true to log "custom columns left blank" warnings
    }
}
$Config.ReportsPath = Join-Path $Config.BasePath "Reports"
$Config.Folders = @{
    TenableInbound   = Join-Path $Config.ReportsPath "Tenable\Inbound"
    TenableProcessed = Join-Path $Config.ReportsPath "Tenable\Processed"
    Scopes           = Join-Path $Config.ReportsPath "Scopes"
    PendingCR        = Join-Path $Config.ReportsPath "PendingCR"
    Validation       = Join-Path $Config.ReportsPath "Validation"
    WeeklyReports    = Join-Path $Config.ReportsPath "WeeklyReports"
    WeeklyArchive    = Join-Path $Config.ReportsPath "WeeklyReports\Archive"
    Resolved         = Join-Path $Config.ReportsPath "Resolved"
    ServiceNow       = Join-Path $Config.ReportsPath "ServiceNow"
    Scripts          = Join-Path $Config.ReportsPath "Scripts"
    DashboardFeed    = Join-Path $Config.ReportsPath "DashboardFeed"
    Config           = Join-Path $Config.ReportsPath "Config"
    Logs             = Join-Path $Config.ReportsPath "Logs"
}
$Config.ServiceNow = @{
    UseActiveCHGExport = $true
    ActiveCHGPath      = Join-Path $Config.Folders.ServiceNow "All Active Vulnerability Management Change Requests.xlsx"
}
$Config.Tenable.LatestCopyPath = Join-Path $Config.ReportsPath "Tenable\latest.csv"
$Config.Reports = @{
    "Workstations"   = @{ ReportPatterns = @("Workstations Vulnerability Manager Report*.xlsx","Workstations*.xlsx"); Category="Workstations" }
    "MS Servers"     = @{ ReportPatterns = @("MS Servers Vulnerability Manager Report*.xlsx","MS Servers*.xlsx","Microsoft Servers*.xlsx"); Category="MS Servers" }
    "Non-MS Servers" = @{ ReportPatterns = @("Non-MS Servers Vulnerability Manager Report*.xlsx","Non-MS Servers*.xlsx","Linux*Report*.xlsx","Unix*Report*.xlsx"); Category="Non-MS Servers" }
}
# In-code defaults
$Config.Defaults = @{
    SkipValidationDefault      = $false
    GenerateDashboardDefault   = $true
    ReportTypesDefault         = @("Workstations", "MS Servers", "Non-MS Servers")
    FastModeDefault            = $true
    NoProgressDefault          = $false
    SkipFormattingDefault      = $true
    ValidationMaxFilesDefault  = 0
    CreateMissingScopesDefault = $true
    ForceReprocessDefault      = $true
}

# Respect defaults if args not supplied
if (-not $PSBoundParameters.ContainsKey('SkipValidation'))      { if ($Config.Defaults.SkipValidationDefault)      { $SkipValidation = $true } }
if (-not $PSBoundParameters.ContainsKey('GenerateDashboard'))   { if ($Config.Defaults.GenerateDashboardDefault)   { $GenerateDashboard = $true } }
if (-not $PSBoundParameters.ContainsKey('ReportTypes'))         { $ReportTypes = $Config.Defaults.ReportTypesDefault }
if (-not $PSBoundParameters.ContainsKey('FastMode'))            { if ($Config.Defaults.FastModeDefault)            { $FastMode = $true } }
if (-not $PSBoundParameters.ContainsKey('NoProgress'))          { if ($Config.Defaults.NoProgressDefault)          { $NoProgress = $true } }
if (-not $PSBoundParameters.ContainsKey('SkipFormatting'))      { if ($Config.Defaults.SkipFormattingDefault)      { $SkipFormatting = $true } }
if (-not $PSBoundParameters.ContainsKey('ValidationMaxFiles'))  { $ValidationMaxFiles = $Config.Defaults.ValidationMaxFilesDefault }
if (-not $PSBoundParameters.ContainsKey('CreateMissingScopes')) { if ($Config.Defaults.CreateMissingScopesDefault) { $CreateMissingScopes = $true } }
if (-not $PSBoundParameters.ContainsKey('ForceReprocess'))      { if ($Config.Defaults.ForceReprocessDefault)      { $ForceReprocess = $true } }

# ================================================================================
# LOGGING / HELPERS
# ================================================================================
function NZ { param($Value,$Default="") if ($null -eq $Value) { $Default } else { $Value } }

$script:LogFile = $null
$script:Perf = @{}
$script:Audit = New-Object System.Collections.ArrayList
$script:AmbiguityLogs = 0
$script:AmbiguityTotal = 0
$script:InvalidIPFiltered = 0
try { Add-Type -AssemblyName System.Drawing | Out-Null } catch {}

function Write-Log {
    param([Parameter(Mandatory=$true)][string]$Message,[ValidateSet("INFO","WARN","ERROR","SUCCESS","STEP")][string]$Level="INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"
    $color = switch($Level){ "STEP"{"Cyan"}; "SUCCESS"{"Green"}; "WARN"{"Yellow"}; "ERROR"{"Red"}; default{"White"} }
    Write-Host $entry -ForegroundColor $color
    if ($script:LogFile -and (Test-Path (Split-Path -Path $script:LogFile -Parent))) { try { Add-Content -Path $script:LogFile -Value $entry -Encoding UTF8 } catch {} }
}
function Add-Audit { param([string]$What,[string]$Detail) if ($What){ if(-not $script:Audit){ $script:Audit = New-Object System.Collections.ArrayList } $null=$script:Audit.Add("$What | $Detail"); Write-Log "AUDIT: $What :: $Detail" } }
function Start-Phase { param([string]$Name) $sw=[Diagnostics.Stopwatch]::StartNew(); $script:Perf[$Name]=@{Stopwatch=$sw;Elapsed=[timespan]::Zero}; Write-Log "▶ $Name" -Level STEP }
function Stop-Phase  { param([string]$Name) if($script:Perf.ContainsKey($Name)){ $script:Perf[$Name].Stopwatch.Stop(); $script:Perf[$Name].Elapsed=$script:Perf[$Name].Stopwatch.Elapsed; Write-Log ("⏱ {0} took {1:N2}s" -f $Name,$script:Perf[$Name].Elapsed.TotalSeconds) } }
function Update-Progress { param([int]$Id,[string]$Activity,[string]$Status="",[int]$PercentComplete=0,[string]$CurrentOperation=$null) if($NoProgress){return}; try { if($PSBoundParameters.ContainsKey('CurrentOperation')){Write-Progress -Id $Id -Activity $Activity -Status $Status -PercentComplete $PercentComplete -CurrentOperation $CurrentOperation}else{Write-Progress -Id $Id -Activity $Activity -Status $Status -PercentComplete $PercentComplete} } catch {} }
function Complete-Progress { param([int]$Id,[string]$Activity="") if(-not $NoProgress){ try { Write-Progress -Id $Id -Activity $Activity -Completed } catch {} } }

function _UpperTrim([string]$s){ if([string]::IsNullOrWhiteSpace($s)) { "" } else { $s.Trim().ToUpperInvariant() } }

# Universal safe-trim (prevents [System.Double].Trim crashes)
function STrim { param($x)
    if($null -eq $x){ return "" }
    $s = $x -as [string]
    if([string]::IsNullOrWhiteSpace($s)){ return "" }
    return $s.Trim()
}

# Retry open (handles transient locks)
function Open-ExcelPackageWithRetry { param([string]$Path,[int]$MaxAttempts=3,[int]$DelayMs=500)
    for($a=1;$a -le $MaxAttempts;$a++){
        try{ return Open-ExcelPackage -Path $Path } catch {
            if($a -ge $MaxAttempts){ throw }
            Start-Sleep -Milliseconds $DelayMs
        }
    }
}

# IPv4 validation
function Test-IPv4 { param([string]$Text)
    if([string]::IsNullOrWhiteSpace($Text)){ return $false }
    $ip=$null
    if([System.Net.IPAddress]::TryParse($Text.Trim(),[ref]$ip)){
        return ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork)
    }
    return $false
}

# General helpers
function Ensure-NoteProperty { param([psobject]$Obj,[string]$Name,[object]$Default=$null) if(-not ($Obj.PSObject.Properties.Name -contains $Name)){ $Obj | Add-Member -NotePropertyName $Name -NotePropertyValue $Default -Force } }
function Get-WorksheetHeaders { param([string]$Path,[string]$SheetName)
    $pkg = Open-ExcelPackageWithRetry -Path $Path
    try{
        $ws=$pkg.Workbook.Worksheets[$SheetName]; if(-not $ws -or -not $ws.Dimension){ return @() }
        $out=@(); for($c=1;$c -le $ws.Dimension.End.Column;$c++){ $h=($ws.Cells[1,$c].Text).Trim(); if($h){ $out+=$h } }
        $out
    } finally { if($pkg){ $pkg.Dispose() } }
}
function Insert-HeaderAfter { param([string[]]$Headers,[string]$NewHeader,[string]$AfterHeader)
    if($Headers -contains $NewHeader){ return ,$Headers }
    $res=@()
    $inserted=$false
    for($i=0;$i -lt $Headers.Count;$i++){
        $res += $Headers[$i]
        if((-not $inserted) -and ($Headers[$i] -eq $AfterHeader)){
            $res += $NewHeader
            $inserted=$true
        }
    }
    if(-not $inserted){ $res += $NewHeader }
    ,$res
}
function Dedup-Headers { param([string[]]$Headers)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $res=@()
    foreach($h in $Headers){
        if(-not $seen.Contains($h)){ [void]$seen.Add($h); $res+=$h }
        else { Write-Log "Duplicate header ignored in template: $h" -Level WARN }
    }
    ,$res
}

# $PSDefaultParameterValues: central default for Export-Excel
try { if(-not $PSDefaultParameterValues){ $Global:PSDefaultParameterValues = @{} }
      $Global:PSDefaultParameterValues['Export-Excel:NoNumberConversion'] = $true } catch {}

# Caches
$script:AliasIndex        = $null
$script:PluginGroups      = $null
$script:PluginIdToFamily  = $null
$script:VulnLookup        = $null

$PROG_MAIN=1; $PROG_IMPORT=2; $PROG_WEEKLY=3; $PROG_FINDINGS=4; $PROG_VALIDATIONS=5; $PROG_ARCHIVE=6; $PROG_DASHBOARD=7

# ================================================================================
# ENV INIT
# ================================================================================
function Initialize-Environment {
    Write-Log "Initializing environment..." -Level STEP
    foreach($key in $Config.Folders.Keys){
        $folder=$Config.Folders[$key]
        if(-not (Test-Path $folder)){ try{ New-Item -Path $folder -ItemType Directory -Force | Out-Null; Write-Log "Created folder: $folder" } catch{ Write-Log "Failed to create ${folder}: $_" -Level ERROR; throw } }
    }
    if(-not $script:LogFile){ $script:LogFile = Join-Path $Config.Folders.Logs ("VulnMgmt_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss')); Write-Log "Log file: $script:LogFile" }
    try{
        if(-not (Get-Module -ListAvailable ImportExcel)){
            try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
            Write-Log "Installing ImportExcel..." -Level WARN
            Install-Module ImportExcel -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        }
        Import-Module ImportExcel -DisableNameChecking -ErrorAction Stop
        Write-Log "ImportExcel loaded" -Level SUCCESS
    } catch { Write-Log "ImportExcel error: $_" -Level ERROR; throw }
    Initialize-ConfigFiles
}
function Initialize-ConfigFiles {
    $tagMapPath = Join-Path $Config.Folders.Config "TagMapping.json"
    $famMapPath = Join-Path $Config.Folders.Config "FamilyMapping.json"
    if(-not (Test-Path $tagMapPath)){
        $tagMap = @{
            "MS Servers"     = @("Windows Server","Microsoft Server","MS-SQL","Exchange","AD")
            "Workstations"   = @("Windows 10","Windows 11","Desktop","Laptop","WS")
            "Non-MS Servers" = @("Linux","Unix","VMware","Network","Appliance","Ubuntu","RHEL","CentOS")
        }
        $tagMap | ConvertTo-Json -Depth 3 | Set-Content -Path $tagMapPath -Encoding UTF8
        Write-Log "Created TagMapping.json"
    }
    if(-not (Test-Path $famMapPath)){
        $famMap = @{
            "Microsoft"     = @("Microsoft*","*Windows*","*Office*","*SQL Server*")
            "Adobe"         = @("Adobe*")
            "Oracle"        = @("Oracle*","*Java*")
            "OpenSSL"       = @("OpenSSL*","*SSL*")
            "Mozilla"       = @("*Firefox*","*Mozilla*")
            "Apache"        = @("Apache*")
            "Google Chrome" = @("*Chrome*","*Chromium*")
        }
        $famMap | ConvertTo-Json -Depth 3 | Set-Content -Path $famMapPath -Encoding UTF8
        Write-Log "Created/Updated FamilyMapping.json"
    }
}

# ================================================================================
# DISCOVERY
# ================================================================================
function Get-LatestTenableCSV {
    Write-Log "Finding latest Tenable CSV..." -Level STEP
    $c=@()
    $dl = Join-Path $env:USERPROFILE "Downloads"
    if(Test-Path $dl){ $c += Get-ChildItem -Path $dl -File -Filter *.csv -ErrorAction SilentlyContinue }
    if(Test-Path $Config.Folders.TenableInbound){ $c += Get-ChildItem -Path $Config.Folders.TenableInbound -File -Filter *.csv -ErrorAction SilentlyContinue }
    $legacy = Join-Path $Config.ReportsPath "Tenable"
    if(Test-Path $legacy){ $c += Get-ChildItem -Path $legacy -File -Filter *.csv -ErrorAction SilentlyContinue }
    if(-not $c){ throw "No CSVs in Downloads/Inbound/Tenable." }

    # Sort all by LastWriteTime (desc), prefer name match if present, but never miss the newest file
    $sortedCandidates = $c | Sort-Object LastWriteTime -Descending
    $newestFile = $sortedCandidates | Select-Object -First 1
    if ($newestFile.Name -match '(?i)tenable|vulnerab|plugin|scan') {
        $pick = $newestFile
    } else {
        $preferred = $sortedCandidates | Where-Object { $_.Name -match '(?i)tenable|vulnerab|plugin|scan' } | Select-Object -First 1
        $pick = if ($preferred) { $preferred } else { $newestFile }
    }
    Write-Log "Using CSV: $($pick.FullName)" -Level SUCCESS
    $pick.FullName
}
function Get-LatestReportFile { param([string]$Folder,[string[]]$Patterns)
    if(-not (Test-Path $Folder)){ Write-Log "WeeklyReports not found: $Folder" -Level WARN; return $null }
    $files=@(); foreach($p in $Patterns){ $files += Get-ChildItem -Path $Folder -File -Filter $p -ErrorAction SilentlyContinue }
    if(-not $files){ return $null }
    ($files | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}

# ================================================================================
# IMPORT CSV + NORMALIZE (with quality gate)
# ================================================================================
function Import-TenableCSV { param([Parameter(Mandatory=$true)][string]$CsvPath)
    Start-Phase -Name "CSV Import/Normalize"
    try{
        $data = Import-Csv -Path $CsvPath
        if(-not $data -or $data.Count -eq 0){ throw "CSV appears empty: $CsvPath" }

        $aliasMap = @{
            'plugin.id'          = 'definition.id'
            'plugin.name'        = 'definition.name'
            'asset.hostname'     = 'asset.name'
            'asset.fqdn'         = 'asset.name'
            'asset.netbios_name' = 'asset.name'
            'asset.ipv4'         = 'asset.display_ipv4_address'
            'asset.ip_address'   = 'asset.display_ipv4_address'
            'ipv4'               = 'asset.display_ipv4_address'
            'host-ip'            = 'asset.display_ipv4_address'
            'last_seen'          = 'last_seen'
            'state'              = 'state'
            'severity'           = 'severity'
        }
        $headers = $data[0].PSObject.Properties.Name
        $apply=@{}; foreach($k in $aliasMap.Keys){ if($headers -contains $k){ $apply[$k]=$aliasMap[$k] } }

        $total=$data.Count
        $bad=0
        for($i=0; $i -lt $total; $i++){
            $o=$data[$i]
            foreach($k in $apply.Keys){
                $t=$apply[$k]
                if(-not ($o.PSObject.Properties.Name -contains $t)){ $o | Add-Member -NotePropertyName $t -NotePropertyValue $o.$k -Force }
            }
            $plugIdTmp = (STrim $o.'definition.id')
            $an  = (STrim $o.'asset.name')
            if([string]::IsNullOrWhiteSpace($plugIdTmp) -or [string]::IsNullOrWhiteSpace($an)){ $bad++ }
            if(($i % 20000) -eq 0){ Update-Progress -Id $PROG_IMPORT -Activity "Importing CSV" -Status "Normalizing ($i of $total)..." -PercentComplete ([int](($i/[double]$total)*100)) }
        }

        $required = @('asset.name','asset.display_ipv4_address','definition.id','definition.name','severity','last_seen','state')
        $missing  = $required | Where-Object { $_ -notin $data[0].PSObject.Properties.Name }
        if($missing){ Write-Log "WARNING: Missing columns post-normalization: $($missing -join ', ')" -Level WARN }

        $pct = if($total -gt 0){ [math]::Round(($bad*100.0)/$total,2) } else { 0 }
        if($pct -gt $Config.Quality.CriticalFieldMissingThresholdPercent){
            throw ("{0}% of rows lack definition.id or asset.name (threshold {1}%). Aborting import." -f $pct,$Config.Quality.CriticalFieldMissingThresholdPercent)
        } elseif($bad -gt 0){
            Write-Log ("{0}% of rows lack critical fields; they will be skipped where relevant." -f $pct) -Level WARN
        }

        # -- KEEP ONLY NEEDED COLUMNS (memory win) --------------------------
        $data = $data | ForEach-Object {
          [pscustomobject]@{
            'asset.name'                = $_.'asset.name'
            'asset.fqdn'                = $_.'asset.fqdn'
            'asset.hostname'            = $_.'asset.hostname'
            'asset.netbios_name'        = $_.'asset.netbios_name'
            'asset.display_ipv4_address'= $_.'asset.display_ipv4_address'
            'definition.id'             = $_.'definition.id'
            'definition.name'           = $_.'definition.name'
            'severity'                  = $_.'severity'
            'last_seen'                 = $_.'last_seen'
            'state'                     = $_.'state'
            'definition.solution'       = $_.'definition.solution'
            'output'                    = $_.'output'
            'ipv4'                      = $_.'ipv4'
            'host-ip'                   = $_.'host-ip'
          }
        }
        # -------------------------------------------------------------------

        Write-Log "Imported records: $($data.Count)" -Level SUCCESS
        $data
    } catch { Write-Log "Import failed: $_" -Level ERROR; throw }
    finally { Complete-Progress -Id $PROG_IMPORT -Activity "Importing CSV"; Stop-Phase -Name "CSV Import/Normalize" }
}

# ================================================================================
# FAMILY / CATEGORY
# ================================================================================
function Get-VulnerabilityFamily { param([string]$VulnName)
    if([string]::IsNullOrWhiteSpace($VulnName)){ return "Miscellaneous" }
    $familyMappingPath = Join-Path $Config.Folders.Config "FamilyMapping.json"
    if(Test-Path $familyMappingPath){
        $map = Get-Content $familyMappingPath | ConvertFrom-Json
        foreach($fam in $map.PSObject.Properties){
            foreach($pat in $fam.Value){ if($VulnName -like $pat){ return $fam.Name } }
        }
    }
    switch -Wildcard ($VulnName){
        "*Google*Chrome*" { "Google Chrome" ; break }
        "*Chromium*"      { "Google Chrome" ; break }
        "*Microsoft Office*" { "Microsoft Office"; break }
        "*Microsoft*KB*"  { "Microsoft KB"; break }
        "*Microsoft*.NET Core*" { "Microsoft .NET Core"; break }
        "*Microsoft*.NET Framework*" { "Microsoft .NET Framework"; break }
        "*Visual Basic*"  { "Microsoft Visual Basic"; break }
        "*SQL Server*"    { "Microsoft SQL"; break }
        "*Microsoft SQL*" { "Microsoft SQL"; break }
        "*Microsoft*"     { "Microsoft Out-of-Band"; break }
        "*OpenSSL*"       { "OpenSSL"; break }
        "*SSL*"           { "SSL"; break }
        "Adobe*"          { "Adobe"; break }
        "Amazon Corretto*" { "Amazon Corretto"; break }
        "Apache*"        { "Apache"; break }
        "Dell*"          { "Dell"; break }
        "IBM*"           { "IBM"; break }
        "Intel*"         { "Intel"; break }
        "*Mozilla Firefox*" { "Mozilla Firefox"; break }
        "*Oracle Java*"   { "Oracle Java"; break }
        "*Oracle*"        { "Oracle"; break }
        "*Windows*Reboot*" { "Windows Reboot"; break }
        default           { "Miscellaneous" }
    }
}
function Categorize-Asset { param([string]$AssetName,[string]$AssetDetails="")
    $tagMapPath = Join-Path $Config.Folders.Config "TagMapping.json"
    if(Test-Path $tagMapPath){
        $tagMap = Get-Content $tagMapPath | ConvertFrom-Json
        foreach($cat in $tagMap.PSObject.Properties){
            foreach($tag in $cat.Value){
                if($AssetName -like "*$tag*" -or $AssetDetails -like "*$tag*"){ return $cat.Name }
            }
        }
    }
    if($AssetName -match "(?i)(server|srv|dc\d+|sql|exchange|ad\d+)"){ "MS Servers" }
    elseif($AssetName -match "(?i)(workstation|desktop|laptop|pc\d+|ws\d+)"){ "Workstations" }
    else { "Non-MS Servers" }
}

# ================================================================================
# CACHES
# ================================================================================
function Build-AssetAliasIndex { param([array]$VulnData)
    $index    = New-Object 'System.Collections.Generic.Dictionary[string,string]'
    $canonSet = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach($r in $VulnData){
        $canon = _UpperTrim ($r.'asset.name'); if(-not $canon){ continue }
        [void]$canonSet.Add($canon)
        $aliases = @()
        $aliases += $canon
        $v = _UpperTrim ($r.'asset.fqdn');               if($v){ $aliases += $v; if($v -match '^[^.]+'){ $aliases += (_UpperTrim ($v.Split('.')[0])) } }
        $v = _UpperTrim ($r.'asset.hostname');           if($v){ $aliases += $v }
        $v = _UpperTrim ($r.'asset.netbios_name');       if($v){ $aliases += $v }
        $v = _UpperTrim ($r.'asset.display_ipv4_address'); if($v){ $aliases += $v }
        foreach($a in ($aliases | Select-Object -Unique)){ if(-not $index.ContainsKey($a)){ $index[$a] = $canon } }
    }
    ,$index,$canonSet.Count
}
function Build-PluginGroups { param([array]$VulnData)
    $groups = @{}
    $id2fam = @{}
    foreach($v in $VulnData){
        $k = STrim $v.'definition.id'; if(-not $k){ continue }
        if(-not $groups.ContainsKey($k)){ $groups[$k] = New-Object System.Collections.Generic.List[object] }
        [void]$groups[$k].Add($v)
        if(-not $id2fam.ContainsKey($k)){ $id2fam[$k] = Get-VulnerabilityFamily -VulnName $v.'definition.name' }
    }
    ,$groups,$id2fam
}
function Build-VulnerabilityLookup { param([array]$VulnData)
    if(-not $script:AliasIndex){ $script:AliasIndex,$null = Build-AssetAliasIndex -VulnData $VulnData }
    $lookup = @{}
    $count  = 0
    foreach($v in $VulnData){
        $assetName = _UpperTrim ($v.'asset.name')
        $pluginId  = STrim $v.'definition.id'; if(-not $pluginId){ continue }
        if($script:AliasIndex.ContainsKey($assetName)){ $assetName = $script:AliasIndex[$assetName] }
        $k = "$assetName|$($pluginId.ToUpperInvariant())"
        if(-not $lookup.ContainsKey($k)){ $lookup[$k] = $v; $count++ }
    }
    ,$lookup,$count
}

# Build caches once & reuse (called after import)
function Initialize-GlobalCaches { param([array]$VulnData)
    $script:AliasIndex,$null                      = Build-AssetAliasIndex -VulnData $VulnData
    $script:PluginGroups,$script:PluginIdToFamily = Build-PluginGroups -VulnData $VulnData
    $script:VulnLookup,$null                      = Build-VulnerabilityLookup -VulnData $VulnData
}

# Optional pre-split by category (not strictly required by later code)
function Split-DataByCategory { param([array]$VulnData)
    $by = @{ 'Workstations'=@(); 'MS Servers'=@(); 'Non-MS Servers'=@() }
    foreach($v in $VulnData){
        $cat = Categorize-Asset -AssetName $v.'asset.name'
        if(-not $by.ContainsKey($cat)){ $by[$cat]=@() }
        $by[$cat] += $v
    }
    return $by
}

# ================================================================================
# SNOW / SCOPES
# ================================================================================
function Get-FamilyScopeMap {
    $map=@{}
    if(-not (Test-Path $Config.Folders.Scopes)){ return $map }
    $files = Get-ChildItem -Path $Config.Folders.Scopes -File -Filter *.xlsx -Recurse -ErrorAction SilentlyContinue
    foreach($f in $files){
        $name=$f.BaseName; $chg=$null
        if($name -match '(?i)(CHG\d{4,9})'){ $chg=$matches[1].ToUpper() }
        $familyToken = ($name -replace '(?i)CHG\d{4,9}\s*-\s*','')
        if([string]::IsNullOrWhiteSpace($familyToken) -or [string]::IsNullOrWhiteSpace($chg)){ continue }
        $fam = Get-VulnerabilityFamily -VulnName $familyToken
        if(-not $map.ContainsKey($fam)){ $map[$fam]=@{} }
        $map[$fam][$chg] = $f.LastWriteTime
    }
    $map
}
function Import-ActiveCHGs {
    if(-not $Config.ServiceNow.UseActiveCHGExport){ return @{} }
    $file = $Config.ServiceNow.ActiveCHGPath
    if([string]::IsNullOrWhiteSpace($file) -or -not (Test-Path $file)){ Write-Log "ServiceNow export not found: $file" -Level WARN; return @{} }
    try{
        Write-Log "Loading ServiceNow Active CHG export..." -Level INFO
        $rows=@()
        if($file -match '\.xlsx$'){
            $si = Get-ExcelSheetInfo -Path $file | Where-Object { -not $_.Hidden } | Select-Object -First 1
            if($si){ $rows = Import-Excel -Path $file -WorksheetName $si.Name }
        } else { $rows = Import-Csv -Path $file }
        if(-not $rows -or $rows.Count -eq 0){ return @{} }

        $h = $rows[0].PSObject.Properties.Name
        $chgCol   = ($h | Where-Object { $_ -match '(?i)^(number|change\s*number|chg(\s*id)?)$' } | Select-Object -First 1)
        $titleCol = ($h | Where-Object { $_ -match '(?i)^(short\s*description|description|scope|family|title)$' } | Select-Object -First 1)
        if(-not $chgCol -or -not $titleCol){ Write-Log "SNOW export missing CHG/Title columns." -Level WARN; return @{} }

        $map=@{}
        foreach($r in $rows){
            $chg=STrim $r.$chgCol; $title=STrim $r.$titleCol
            if([string]::IsNullOrWhiteSpace($chg) -or [string]::IsNullOrWhiteSpace($title)){ continue }
            $fam = Get-VulnerabilityFamily -VulnName $title
            if(-not $map.ContainsKey($fam)){ $map[$fam]=@{} }
            $map[$fam][$chg.ToUpper()] = Get-Date
        }
        Write-Log "Loaded $($rows.Count) CHG rows." -Level SUCCESS
        $map
    } catch { Write-Log "SNOW parse failed: $_" -Level WARN; @{} }
}
function Get-ActiveCHGSetAndMeta {
    $res=@{ Set=@{}; Meta=@{} }
    $file=$Config.ServiceNow.ActiveCHGPath
    if(-not (Test-Path $file)){ return $res }
    try{
        $si = Get-ExcelSheetInfo -Path $file | Where-Object { -not $_.Hidden } | Select-Object -First 1
        if(-not $si){ return $res }
        $rows = Import-Excel -Path $file -WorksheetName $si.Name
        if(-not $rows -or $rows.Count -eq 0){ return $res }
        $h = $rows[0].PSObject.Properties.Name
        $chgCol   = ($h | Where-Object { $_ -match '(?i)^(number|change\s*number|chg(\s*id)?)$' } | Select-Object -First 1)
        $startCol = ($h | Where-Object { $_ -match '(?i)planned\s*start|start\s*date' } | Select-Object -First 1)
        $endCol   = ($h | Where-Object { $_ -match '(?i)planned\s*end|end\s*date' } | Select-Object -First 1)
        $titleCol = ($h | Where-Object { $_ -match '(?i)^(short\s*description|description|scope|family|title)$' } | Select-Object -First 1)
        foreach($r in $rows){
            $chg=STrim $r.$chgCol; if(-not $chg){ continue }
            $chg=$chg.ToUpper()
            if($chg -notmatch '^CHG\d{4,9}$'){ continue }
            $res.Set[$chg]=$true
            $res.Meta[$chg]=@{ Title=(NZ (STrim $r.$titleCol)); PlannedStart=(NZ (STrim $r.$startCol)); PlannedEnd=(NZ (STrim $r.$endCol)) }
        }
    } catch { Write-Log "Active CHG set build failed: $_" -Level WARN }
    $res
}
function Get-OfficialCHGForFamily { param([hashtable]$SNOWFamilyMap,[hashtable]$ScopeFamilyMap,[string]$Family,[string]$FallbackPT)
    if($SNOWFamilyMap -and $SNOWFamilyMap.ContainsKey($Family)){
        $h=$SNOWFamilyMap[$Family]; $best=$null; $bestTime=(Get-Date '1900-01-01')
        foreach($k in $h.Keys){ if($h[$k] -gt $bestTime){ $bestTime=$h[$k]; $best=$k } }
        if($best){ return @{ CHG=$best; Date=$bestTime } }
    }
    if($FallbackPT -match '(?i)^CHG\d{4,9}$' -and $ScopeFamilyMap){
        foreach($fam in $ScopeFamilyMap.Keys){ $inner=$ScopeFamilyMap[$fam]; if($inner.ContainsKey($FallbackPT.ToUpper())){ return @{ CHG=$FallbackPT.ToUpper(); Date=$inner[$FallbackPT.ToUpper()] } } }
    }
    $null
}
function Try-ResolveCHG { param([string]$Family,[string]$CurrentPT,[hashtable]$SNOWFamilyMap,[hashtable]$ScopeFamilyMap)
    $info = $null
    if(-not [string]::IsNullOrWhiteSpace($Family)){
        $info = Get-OfficialCHGForFamily -SNOWFamilyMap $SNOWFamilyMap -ScopeFamilyMap $ScopeFamilyMap -Family $Family -FallbackPT $CurrentPT
    }
    if($info){ return $info }
    $pt=(NZ $CurrentPT).Trim().ToUpper()
    if($pt -match '^CHG\d{4,9}$'){
        $dt = Find-CHGDateFallback -ScopeFamilyMap $ScopeFamilyMap -Chg $pt
        return @{ CHG=$pt; Date=$dt }
    }
    $null
}

# ================================================================================
# WEEKLY REPORTS
# ================================================================================
function Backup-WeeklyReport { param([string]$ReportPath,[string]$ReportType)
    try{
        if(-not (Test-Path $ReportPath)){ return }
        $dateFolder=(Get-Date -Format 'yyyy-MM-dd'); $yearFolder=(Get-Date -Format 'yyyy')
        $destRoot = Join-Path $Config.Folders.WeeklyArchive $ReportType
        $dest = Join-Path (Join-Path $destRoot $yearFolder) $dateFolder
        if(-not (Test-Path $dest)){ New-Item -Path $dest -ItemType Directory -Force | Out-Null }
        $base=[IO.Path]::GetFileNameWithoutExtension($ReportPath); $ts=(Get-Date -Format 'yyyyMMdd_HHmmss')
        $bakPath = Join-Path $dest ("{0}_{1}.xlsx" -f $base,$ts)
        Copy-Item -Path $ReportPath -Destination $bakPath -Force
        Add-Audit -What "WeeklyBackup" -Detail "$ReportType -> $bakPath"
        Write-Log "Backup created: $bakPath" -Level SUCCESS
    } catch { Write-Log "Backup failed: $_" -Level WARN }
}
function Ensure-WeekColumn { param($Worksheet,[hashtable]$ColMap,[string]$WeekDate)
    if($ColMap.ContainsKey($WeekDate)){ return $ColMap }
    $pluginCol = $ColMap['Plugin ID']; if(-not $pluginCol){ throw "Template missing 'Plugin ID'." }
    $insertIdx = $pluginCol + 1
    $Worksheet.InsertColumn($insertIdx,1)
    $Worksheet.Cells[1,$insertIdx].Value = $WeekDate
    Add-Audit -What "WeekColumnInserted" -Detail "$WeekDate @ col $insertIdx"
    $new=@{}; for($c=1;$c -le $Worksheet.Dimension.End.Column;$c++){ $hdr=($Worksheet.Cells[1,$c].Text).Trim(); if($hdr){ $new[$hdr]=$c } }
    $new
}
function Ensure-LatestChgDateColumn { param($Worksheet,[hashtable]$ColMap,[string]$HeaderName='Latest CHG Date')
    if($ColMap.ContainsKey($HeaderName)){ return $ColMap }
    if(-not $ColMap.ContainsKey('Mitigation Plan')){ throw "Template missing 'Mitigation Plan'." }
    $insertIdx = $ColMap['Mitigation Plan'] + 1
    $Worksheet.InsertColumn($insertIdx,1)
    $Worksheet.Cells[1,$insertIdx].Value = $HeaderName
    Add-Audit -What "LatestChgDateColumnInserted" -Detail "$HeaderName @ col $insertIdx"
    $new=@{}; for($c=1;$c -le $Worksheet.Dimension.End.Column;$c++){ $hdr=($Worksheet.Cells[1,$c].Text).Trim(); if($hdr){ $new[$hdr]=$c } }
    $new
}
function Copy-FilteredRows { param($ExcelPackage,$SourceWs,[hashtable]$ColMap,[string]$SheetName,[scriptblock]$Predicate)
    $existing=$ExcelPackage.Workbook.Worksheets[$SheetName]
    if($existing){
        # EPPlus compatible: delete by name (not object)
        $ExcelPackage.Workbook.Worksheets.Delete($existing.Name)
    }
    $outRows=@()
    for($r=2;$r -le $SourceWs.Dimension.End.Row;$r++){
        $sev=(NZ $SourceWs.Cells[$r,$ColMap['Severity']].Text)
        $status=(NZ $SourceWs.Cells[$r,$ColMap['Status']].Text)
        $pt=(NZ $SourceWs.Cells[$r,$ColMap['Parent Ticket']].Text)
        if(& $Predicate $sev $status $pt){ $outRows += $r }
    }
    if($outRows.Count -eq 0){ return }
    $wsOut=$ExcelPackage.Workbook.Worksheets.Add($SheetName)
    for($c=1;$c -le $SourceWs.Dimension.End.Column;$c++){ $wsOut.Cells[1,$c].Value=$SourceWs.Cells[1,$c].Text }
    $out=2
    foreach($r in $outRows){ for($c=1;$c -le $SourceWs.Dimension.End.Column;$c++){ $wsOut.Cells[$out,$c].Value=$SourceWs.Cells[$r,$c].Text } $out++ }
    if(-not $FastMode -and $Config.Performance.EnableAutoSize -and -not $SkipFormatting){ $wsOut.Cells.AutoFitColumns() }
    Add-Audit -What "RollupSheet" -Detail "${SheetName}: rows=$($out-2)"
}
function Generate-CategoryTabs { param($ExcelPackage,$SourceWs,[hashtable]$ColMap)
    Copy-FilteredRows -ExcelPackage $ExcelPackage -SourceWs $SourceWs -ColMap $ColMap -SheetName "CHGs Completed" -Predicate { param($sev,$status,$pt) ($status -match '^(?i)completed$') }
    Copy-FilteredRows -ExcelPackage $ExcelPackage -SourceWs $SourceWs -ColMap $ColMap -SheetName "Pending - Medium" -Predicate { param($sev,$status,$pt) (($status -match '^(?i)pending$') -and ($sev -match '(?i)medium')) }
    Copy-FilteredRows -ExcelPackage $ExcelPackage -SourceWs $SourceWs -ColMap $ColMap -SheetName "Pending - High" -Predicate   { param($sev,$status,$pt) (($status -match '^(?i)pending$') -and ($sev -match '(?i)high')) }
    Copy-FilteredRows -ExcelPackage $ExcelPackage -SourceWs $SourceWs -ColMap $ColMap -SheetName "Pending - Critical" -Predicate{ param($sev,$status,$pt) (($status -match '^(?i)pending$') -and ($sev -match '(?i)critical')) }
    Copy-FilteredRows -ExcelPackage $ExcelPackage -SourceWs $SourceWs -ColMap $ColMap -SheetName "New CHGs" -Predicate         { param($sev,$status,$pt) ($status -match '^(?i)new$') }
}
function Find-CHGDateFallback { param([hashtable]$ScopeFamilyMap,[string]$Chg)
    if([string]::IsNullOrWhiteSpace($Chg)){ return $null }
    foreach($fam in $ScopeFamilyMap.Keys){ $inner=$ScopeFamilyMap[$fam]; if($inner -and $inner.ContainsKey($Chg.ToUpper())){ return $inner[$Chg.ToUpper()] } }
    $null
}
function Find-LatestValidationOutstandingCountForCHG { param([string]$ChgId)
    $folder = Join-Path $Config.Folders.Validation "Reports"
    if(-not (Test-Path $folder)){ return $null }
    $files = Get-ChildItem -Path $folder -File -Filter "*$ChgId*.xlsx" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    foreach($f in $files){
        try{
            $sum = Import-Excel -Path $f.FullName -WorksheetName 'Summary'
            if($sum -and $sum.Count -gt 0){
                $hdr = $sum[0].PSObject.Properties.Name
                $noCol = ($hdr | Where-Object { $_ -match '^(?i)(no|count|value)$' } | Select-Object -First 1)
                if($noCol){ $val=$sum[0].$noCol; $n=0; if([int]::TryParse([string]$val,[ref]$n)){ return $n } }
                foreach($row in $sum){
                    $totalsCol = ($row.PSObject.Properties.Name | Where-Object { $_ -match '^(?i)totals$' } | Select-Object -First 1)
                    if($totalsCol -and (([string]$row.$totalsCol) -match '(?i)devices\s*outstanding')){
                        $numCol = ($row.PSObject.Properties.Name | Where-Object { $_ -match '^(?i)(no|count|value)$' } | Select-Object -First 1)
                        if($numCol){ $val2=$row.$numCol; $m=0; if([int]::TryParse([string]$val2,[ref]$m)){ return $m } }
                    }
                }
            }
        } catch { continue }
    }
    $null
}

function Compute-Status {
    param(
        [string]$ParentTicket,
        [int]$CurrentCount,
        [hashtable]$ActiveCHGSet,
        [hashtable]$ValidationCache = $null
    )
    $pt = (NZ $ParentTicket "").Trim().ToUpper()
    $hasChg = $pt -match '^CHG\d{4,9}$'
    if ($CurrentCount -le 0) {
        if($Config.Quality.GateCompletedByValidation -and $hasChg -and $ValidationCache){
            if(-not $ValidationCache.ContainsKey($pt)){ $ValidationCache[$pt] = (Find-LatestValidationOutstandingCountForCHG -ChgId $pt) }
            $out = $ValidationCache[$pt]
            if($out -ne $null -and $out -gt 0){ return 'Pending' }
        }
        return 'Completed'
    }
    if ($hasChg) { return 'Pending' }
    if ($pt -eq 'PENDING') { return 'Pending' }
    return 'New'
}

function Process-WeeklyReports { param([array]$VulnData,[string]$WeekDate)
    if(-not $VulnData -or $VulnData.Count -eq 0){ Write-Log "No vulnerability data for weekly reports." -Level WARN; return }
    Start-Phase -Name "Weekly Reports"
    Update-Progress -Id $PROG_WEEKLY -Activity "Weekly Reports" -Status "Preparing..." -PercentComplete 0

    if(-not $script:PluginGroups -or -not $script:AliasIndex -or -not $script:VulnLookup){
        $script:AliasIndex,$null        = Build-AssetAliasIndex -VulnData $VulnData
        $script:PluginGroups,$script:PluginIdToFamily = Build-PluginGroups -VulnData $VulnData
        $script:VulnLookup,$null        = Build-VulnerabilityLookup -VulnData $VulnData
    }

    $scopeMap = Get-FamilyScopeMap
    $snowMap  = Import-ActiveCHGs
    $activeCHGInfo = Get-ActiveCHGSetAndMeta

    $total=$ReportTypes.Count; $i=0
    foreach($reportType in $ReportTypes){
        $i++; Update-Progress -Id $PROG_WEEKLY -Activity "Weekly Reports" -Status "Processing $reportType ($i of $total)" -PercentComplete ([int](($i-1)/[double]$total*100))
        if(-not $Config.Reports.ContainsKey($reportType)){ Write-Log "Unknown report type: $reportType" -Level WARN; continue }
        $rc = $Config.Reports[$reportType]
        $template = Get-LatestReportFile -Folder $Config.Folders.WeeklyReports -Patterns $rc.ReportPatterns
        if(-not $template){ Write-Log "No template found for $reportType" -Level WARN; continue }

        Backup-WeeklyReport -ReportPath $template -ReportType $reportType

        $categoryData = $VulnData | Where-Object { (Categorize-Asset -AssetName $_.'asset.name') -eq $rc.Category }
        if(-not $categoryData -or $categoryData.Count -eq 0){ Write-Log "No vulnerabilities for $($rc.Category)" -Level WARN; continue }

        Update-WeeklyReport -ReportPath $template -VulnData $categoryData -WeekDate $WeekDate -ReportType $reportType `
            -SNOWFamilyMap $snowMap -ScopeFamilyMap $scopeMap -ActiveCHGSet $activeCHGInfo.Set
    }

    Update-Progress -Id $PROG_WEEKLY -Activity "Weekly Reports" -Status "Done" -PercentComplete 100
    Stop-Phase -Name "Weekly Reports"
    Complete-Progress -Id $PROG_WEEKLY -Activity "Weekly Reports"
}

# OPTIMIZED in-memory weekly update (with string-cast fix & micro perf)
function Update-WeeklyReport {
    param(
        [string]$ReportPath,
        [array] $VulnData,
        [string]$WeekDate,
        [string]$ReportType,
        [hashtable]$SNOWFamilyMap,
        [hashtable]$ScopeFamilyMap,
        [hashtable]$ActiveCHGSet
    )
    $pkgOut = $null
    try{
        Write-Log "Updating ${ReportType}: $ReportPath"

        $headers = Get-WorksheetHeaders -Path $ReportPath -SheetName 'Vulnerability Data'
        if(-not $headers -or $headers.Count -eq 0){ throw "Worksheet 'Vulnerability Data' has no headers/data" }

        $must=@('Severity','Plugin Name','Plugin ID','Status','Parent Ticket','Mitigation Plan')
        $miss=$must | Where-Object { $_ -notin $headers }
        if($miss){ throw "Template missing required columns: $($miss -join ', ')" }

        $headers = (Insert-HeaderAfter -Headers $headers -NewHeader 'Latest CHG Date' -AfterHeader 'Mitigation Plan')
        $headers = (Insert-HeaderAfter -Headers $headers -NewHeader $WeekDate -AfterHeader 'Plugin ID')
        $headers = (Dedup-Headers -Headers $headers)

        $known = @('Severity','Plugin Name','Plugin ID','Status','Parent Ticket','Mitigation Plan','Latest CHG Date', $WeekDate)
        $unhandled = $headers | Where-Object { $_ -notin $known }
        if($unhandled.Count -gt 0){
            if($Config.Quality.LogCustomColumnWarn){
                Write-Log ("Template has custom columns left blank by script: {0}" -f ($unhandled -join ', ')) -Level WARN
            }
        }

        $rows = @(Import-Excel -Path $ReportPath -WorksheetName 'Vulnerability Data')

        # Build index of sheet plugin IDs -> row (avoid unnecessary "new row" creation)
        $sheetLookup=@{}
        foreach($r in $rows){
            $pidRaw = NZ $r.'Plugin ID'
            $pidKey = STrim $pidRaw
            if(-not $pidKey){ continue }
            $sheetLookup[$pidKey] = $r
        }

        $plugGroups = @{}
        foreach($v in $VulnData){
            $k = STrim $v.'definition.id'; if(-not $k){ continue }
            if(-not $plugGroups.ContainsKey($k)){ $plugGroups[$k]=New-Object System.Collections.Generic.List[object] }
            [void]$plugGroups[$k].Add($v)
        }

        $familyCHGCache=@{}
        foreach($plugIdKey in $plugGroups.Keys){
            $fam = if($script:PluginIdToFamily -and $script:PluginIdToFamily.ContainsKey($plugIdKey)){ $script:PluginIdToFamily[$plugIdKey] } else { Get-VulnerabilityFamily -VulnName $plugGroups[$plugIdKey][0].'definition.name' }
            if(-not $familyCHGCache.ContainsKey($fam)){ $familyCHGCache[$fam] = Try-ResolveCHG -Family $fam -CurrentPT "" -SNOWFamilyMap $SNOWFamilyMap -ScopeFamilyMap $ScopeFamilyMap }
        }

        $stats=@{NewVulns=0; UpdatedVulns=0; ResolvedVulns=0}
        $processed = New-Object 'System.Collections.Generic.HashSet[string]'
        $validationCache = @{}

        foreach($r in $rows){
            $plugId = STrim $r.'Plugin ID'
            if([string]::IsNullOrWhiteSpace($plugId)){ continue }
            Ensure-NoteProperty -Obj $r -Name $WeekDate -Default 0
            Ensure-NoteProperty -Obj $r -Name 'Latest CHG Date' -Default ""

            $curPT = STrim $r.'Parent Ticket'
            $curMit = (NZ $r.'Mitigation Plan')

            if($plugGroups.ContainsKey($plugId)){
                $grp=$plugGroups[$plugId]
                $count=$grp.Count
                $r | Add-Member -NotePropertyName $WeekDate -NotePropertyValue $count -Force

                $weeksSince = Get-WeeksSinceDiscovery -MitigationPlan $curMit -CurrentWeek $WeekDate
                $note = Get-VulnerabilityLifecycleNote -WeeksSinceDiscovery $weeksSince -CurrentWeek $WeekDate
                if($note){ $r.'Mitigation Plan' = (Add-MitigationNote -ExistingPlan $curMit -NewNote $note -Date $WeekDate) }

                $fam = if($script:PluginIdToFamily -and $script:PluginIdToFamily.ContainsKey($plugId)){ $script:PluginIdToFamily[$plugId] } else { Get-VulnerabilityFamily -VulnName $grp[0].'definition.name' }
                $info = if($familyCHGCache.ContainsKey($fam)){ $familyCHGCache[$fam] } else { $null }
                if(-not $info){ $info = Try-ResolveCHG -Family $fam -CurrentPT $curPT -SNOWFamilyMap $SNOWFamilyMap -ScopeFamilyMap $ScopeFamilyMap }

                if($info){
                    if([string]::IsNullOrWhiteSpace($curPT) -or $curPT -match '^(?i)pending$'){
                        $r.'Parent Ticket' = $info.CHG
                        Add-Audit -What "ParentTicketSet" -Detail "Plugin=$plugId; CHG=$($info.CHG)"
                        $curPT=$info.CHG
                    }
                    if($info.Date){ $r.'Latest CHG Date' = $info.Date.ToString('yyyy-MM-dd') }
                }

                $r.Status = (Compute-Status -ParentTicket $curPT -CurrentCount $count -ActiveCHGSet $ActiveCHGSet -ValidationCache $validationCache)
                [void]$processed.Add($plugId)
                $stats.UpdatedVulns++
            } else {
                $r | Add-Member -NotePropertyName $WeekDate -NotePropertyValue 0 -Force
                $r.'Mitigation Plan' = (Add-MitigationNote -ExistingPlan $curMit -NewNote "Resolved" -Date $WeekDate)
                $newStatus = Compute-Status -ParentTicket $curPT -CurrentCount 0 -ActiveCHGSet $ActiveCHGSet -ValidationCache $validationCache
                $r.Status = $newStatus
                if($newStatus -eq 'Completed'){ $stats.ResolvedVulns++ }
                if($curPT -match '(?i)^CHG\d{4,9}$' -and [string]::IsNullOrWhiteSpace((NZ $r.'Latest CHG Date'))){
                    $dt = Find-CHGDateFallback -ScopeFamilyMap $ScopeFamilyMap -Chg $curPT
                    if($dt){ $r.'Latest CHG Date' = $dt.ToString('yyyy-MM-dd') }
                }
            }
        }

        $newRows=@()
        foreach($plugIdKey in $plugGroups.Keys){
            # skip creating a new row if the sheet already contains this plugin ID
            if($sheetLookup.ContainsKey($plugIdKey)){ continue }
            $grp=$plugGroups[$plugIdKey]; if($grp.Count -eq 0){ continue }
            $s=$grp[0]

            $fam = if($script:PluginIdToFamily -and $script:PluginIdToFamily.ContainsKey($plugIdKey)){ $script:PluginIdToFamily[$plugIdKey] } else { Get-VulnerabilityFamily -VulnName $s.'definition.name' }
            $info = if($familyCHGCache.ContainsKey($fam)){ $familyCHGCache[$fam] } else { $null }

            $newRow = [ordered]@{}
            foreach($h in $headers){
                $newRow[$h] = switch($h){
                    'Severity'         { $s.severity }
                    'Plugin Name'      { $s.'definition.name' }
                    'Plugin ID'        { [string]$plugIdKey }
                    'Status'           { if($info){ (Compute-Status -ParentTicket $info.CHG -CurrentCount $grp.Count -ActiveCHGSet $ActiveCHGSet -ValidationCache $validationCache) } else { 'New' } }
                    'Parent Ticket'    { if($info){ $info.CHG } else { "" } }
                    'Mitigation Plan'  { (Add-MitigationNote -ExistingPlan "" -NewNote "Vulnerabilities discovered" -Date $WeekDate) }
                    'Latest CHG Date'  { if($info -and $info.Date){ $info.Date.ToString('yyyy-MM-dd') } else { "" } }
                    default            { if($h -eq $WeekDate){ $grp.Count } else { "" } }
                }
            }
            if(-not $info){ Add-Audit -What "ScopeMissing(New)" -Detail "Plugin=$plugIdKey; Family=$fam" }
            $newRows += [pscustomobject]$newRow
            $stats.NewVulns++
        }

        $finalData = @()
        foreach($r in $rows){
            foreach($h in $headers){ Ensure-NoteProperty -Obj $r -Name $h -Default "" }
            $finalData += $r
        }
        $finalData += $newRows

        $ts=(Get-Date -Format 'yyyyMMdd_HHmmss')
        $base=[IO.Path]::GetFileNameWithoutExtension($ReportPath)
        $dir=[IO.Path]::GetDirectoryName($ReportPath)
        $outPath = Join-Path $dir ("{0}_{1}.xlsx" -f $base,$ts)
        Copy-Item -Path $ReportPath -Destination $outPath -Force

        $sel = $finalData | Select-Object $headers
        if(-not $FastMode -and $Config.Performance.EnableAutoSize -and -not $SkipFormatting){
            $sel | Export-Excel -Path $outPath -WorksheetName 'Vulnerability Data' -ClearSheet -AutoFilter -FreezeTopRow -AutoSize -NoNumberConversion
        } else {
            $sel | Export-Excel -Path $outPath -WorksheetName 'Vulnerability Data' -ClearSheet -AutoFilter -FreezeTopRow -NoNumberConversion
        }

        # Rebuild tabs + set column formats
        try{
            $pkgOut = Open-ExcelPackageWithRetry -Path $outPath
            $wsOut = $pkgOut.Workbook.Worksheets['Vulnerability Data']
            $colMap=@{}; for($c=1;$c -le $wsOut.Dimension.End.Column;$c++){ $h=($wsOut.Cells[1,$c].Text).Trim(); if($h){ $colMap[$h]=$c } }
            # Force Plugin ID column as text to reduce future numeric coercion
            if($colMap.ContainsKey('Plugin ID')){
                $colIdx = $colMap['Plugin ID']
                $wsOut.Column($colIdx).Style.Numberformat.Format = '@'
            }
            Generate-CategoryTabs -ExcelPackage $pkgOut -SourceWs $wsOut -ColMap $colMap
            $pkgOut.Save()
        } finally {
            if($pkgOut){ try{ $pkgOut.Dispose() }catch{} }
        }

        Write-Log ("{0} update complete => New: {1}, Updated: {2}, Completed (0+valid): {3}" -f $ReportType,$stats.NewVulns,$stats.UpdatedVulns,$stats.ResolvedVulns) -Level SUCCESS
        Write-Log "Updated file: $outPath" -Level SUCCESS
    } catch {
        Write-Log "Failed to update ${ReportType}: $_" -Level ERROR
    }
}

# ================================================================================
# FINDINGS / VALIDATIONS (NetBIOS→IP→Name→FQDN)
# ================================================================================
function Try-ParseDate {
    param([string]$Text)
    if([string]::IsNullOrWhiteSpace($Text)){ return $null }
    $t = ($Text -replace 'UTC','').Trim()
    $dt = $null
    if([datetime]::TryParse($t,[ref]$dt)){ return $dt }
    try { return [datetime]$t } catch { return $null }
}
function Get-AssetKeyVariantsFromRow { param($Row)
    if($null -eq $Row){ return @() }
    if($Row -is [string]){ return (Get-AssetKeyVariantsFromText -Text $Row) }
    $vals = New-Object 'System.Collections.Generic.HashSet[string]'
    $candidates = @(
        ($Row.'asset.name' -as [string]),
        ($Row.'asset.fqdn' -as [string]),
        ($Row.'asset.hostname' -as [string]),
        ($Row.'asset.netbios_name' -as [string]),
        ($Row.'asset.display_ipv4_address' -as [string]),
        ($Row.'ipv4' -as [string]),
        ($Row.'host-ip' -as [string])
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    foreach($v in $candidates){
        $t=$v.Trim()
        if([string]::IsNullOrWhiteSpace($t)){ continue }
        [void]$vals.Add($t.ToUpperInvariant())
        if($t -match '^[A-Za-z0-9\-]+\.[A-Za-z0-9\.\-]+$'){
            $short=$t.Split('.')[0]
            if(-not [string]::IsNullOrWhiteSpace($short)){ [void]$vals.Add($short.ToUpperInvariant()) }
        }
    }
    return [string[]]$vals
}
function Get-AssetKeyVariantsFromText { param([string]$Text)
    $vals = New-Object 'System.Collections.Generic.HashSet[string]'
    if([string]::IsNullOrWhiteSpace($Text)){ return @() }
    $t=$Text.Trim()
    [void]$vals.Add($t.ToUpperInvariant())
    if($t -match '^[A-Za-z0-9\-]+\.[A-Za-z0-9\.\-]+$'){
        $short=$t.Split('.')[0]
        if(-not [string]::IsNullOrWhiteSpace($short)){ [void]$vals.Add($short.ToUpperInvariant()) }
    }
    return [string[]]$vals
}
function Build-ValidationLookup { param([array]$VulnData)
    $lookup = @{ NETBIOS=@{}; IP=@{}; NAME=@{}; FQDN=@{} }
    $add = {
        param([hashtable]$bucket,[string]$val,[string]$pkey,[object]$row)
        if([string]::IsNullOrWhiteSpace($val)){ return }
        $k = (STrim $val).ToUpperInvariant() + '_' + $pkey
        if(-not $bucket.ContainsKey($k)){ $bucket[$k] = $row }
    }
    foreach($v in $VulnData){
        $plugKey = (STrim $v.'definition.id').ToUpperInvariant(); if(-not $plugKey){ continue }

        & $add $lookup.NETBIOS ($v.'asset.netbios_name') $plugKey $v

        $hn = STrim $v.'asset.hostname'
        if($hn){
            if($hn -match '\.'){ & $add $lookup.FQDN $hn $plugKey $v } else { & $add $lookup.NETBIOS $hn $plugKey $v }
        }

        # Build IP candidates (Option B: most readable)
        $ipCandidates = @()
        $ipCandidates += (STrim $v.'asset.display_ipv4_address')
        $ipCandidates += (STrim $v.'ipv4')
        $ipCandidates += (STrim $v.'host-ip')

        foreach($ipField in $ipCandidates){
            if(-not [string]::IsNullOrWhiteSpace($ipField)){
                if(Test-IPv4 -Text $ipField){ & $add $lookup.IP $ipField $plugKey $v }
                else {
                    $script:InvalidIPFiltered++
                    # Noise reduction: per-row audits disabled
                }
            }
        }

        & $add $lookup.NAME ($v.'asset.name') $plugKey $v
        & $add $lookup.FQDN ($v.'asset.fqdn') $plugKey $v
    }
    $lookup
}
function Match-VulnByPriority {
    param([string]$AssetText,[string]$PluginId,[hashtable]$Lookup,[string]$ScopeName)
    if([string]::IsNullOrWhiteSpace($AssetText) -or [string]::IsNullOrWhiteSpace($PluginId)){ return $null }
    $plugKey = (STrim $PluginId).ToUpperInvariant()
    $raw = (STrim $AssetText).ToUpperInvariant()
    $isIp   = (Test-IPv4 -Text $raw)
    $isFqdn = ($raw -match '^[A-Z0-9\-]+\.[A-Z0-9\.\-]+$')
    $short = $null; if($isFqdn){ $short = $raw.Split('.')[0] }
    $candidates = @{ NETBIOS=@(); IP=@(); NAME=@(); FQDN=@() }
    if($short){ $candidates.NETBIOS += $short }
    if((-not $isFqdn) -and (-not $isIp)){ $candidates.NETBIOS += $raw }
    if($isIp){ $candidates.IP += $raw }
    $candidates.NAME += $raw
    if($isFqdn){ $candidates.FQDN += $raw }
    foreach($k in @('NETBIOS','IP','NAME','FQDN')){ $candidates[$k] = $candidates[$k] | Select-Object -Unique }
    $found = @()
    foreach($type in @('NETBIOS','IP','NAME','FQDN')){
        foreach($val in $candidates[$type]){
            $key = "$val`_$plugKey"
            if($Lookup[$type].ContainsKey($key)){ $found += [pscustomobject]@{ Type=$type; Key=$val; Row=$Lookup[$type][$key] } }
    }
    }
    if($found.Count -gt 1){
        $script:AmbiguityTotal++
        if($script:AmbiguityLogs -lt $Config.Quality.AmbiguityLogLimit){
            $assets = ($found |
              Where-Object { $_.Row } |
              Select-Object -ExpandProperty Row |
              Select-Object -ExpandProperty 'asset.name' -Unique) -join ', '
            Add-Audit -What "AmbiguousAssetMatch" -Detail ("Scope={0}; Plugin={1}; Tried={2}; Assets={3}" -f $ScopeName,$plugKey,($candidates.NETBIOS + $candidates.IP + $candidates.NAME + $candidates.FQDN -join '|'),$assets)
            $script:AmbiguityLogs++
        }
    }
    if($found.Count -gt 0){
        $order = @{ NETBIOS=1; IP=2; NAME=3; FQDN=4 }
        return ($found | Sort-Object @{Expression={ $order[$_.Type] }}, @{Expression={$_.Key.Length};Descending=$true} | Select-Object -First 1).Row
    }
    return $null
}

function Generate-FindingsReport { param([string]$Family,[array]$VulnData)
    try{
        if(-not $VulnData -or $VulnData.Count -eq 0){ return }
        $timestamp=Get-Date -Format "MMdd"; $fileName="$Family Findings $timestamp.xlsx"
        $sampleAsset = $VulnData[0].'asset.name'
        $category = Categorize-Asset -AssetName $sampleAsset
        $outFolder = Join-Path $Config.Folders.PendingCR $category
        if(-not (Test-Path $outFolder)){ New-Item -Path $outFolder -ItemType Directory -Force | Out-Null }
        $outPath = Join-Path $outFolder $fileName

        $export = $VulnData |
            Sort-Object severity,'definition.id' |
            Select-Object @{n='Severity';e={$_.severity}},
                          @{n='Plugin ID';e={$_.'definition.id'}},
                          @{n='Plugin Name';e={$_.'definition.name'}},
                          @{n='Asset Name';e={$_.'asset.name'}},
                          @{n='IP Address';e={$_.'asset.display_ipv4_address'}},
                          @{n='Last Seen';e={$_.last_seen}},
                          @{n='Solution';e={$_.'definition.solution'}},
                          @{n='Output';e={$_.'output'}}

        if(-not $FastMode -and $Config.Performance.EnableAutoSize -and -not $SkipFormatting){
            $export | Export-Excel -Path $outPath -WorksheetName "Findings" -AutoFilter -AutoSize -NoNumberConversion
        } else {
            $export | Export-Excel -Path $outPath -WorksheetName "Findings" -AutoFilter -NoNumberConversion
        }

        $summary = $VulnData | Group-Object severity | Select-Object @{n='Severity';e={$_.Name}},@{n='Count';e={$_.Count}}
        if(-not $FastMode -and $Config.Performance.EnableAutoSize -and -not $SkipFormatting){
            $summary | Export-Excel -Path $outPath -WorksheetName "Summary" -AutoSize -NoNumberConversion
        } else {
            $summary | Export-Excel -Path $outPath -WorksheetName "Summary" -NoNumberConversion
        }
        Write-Log "Generated findings: $outPath" -Level SUCCESS
    } catch { Write-Log "Findings failed ($Family): $_" -Level ERROR }
}
function Create-FamilyScopeIfMissing { param([string]$Family,[array]$VulnDataForFamily)
    Add-Audit -What "CreateScopeStub" -Detail ("Family={0}; Plugins={1}" -f $Family, ($VulnDataForFamily.'definition.id' | Select-Object -Unique | Measure-Object | Select-Object -ExpandProperty Count))
    Generate-FindingsReport -Family $Family -VulnData $VulnDataForFamily
}
function Detect-NewFindings { param([array]$VulnData)
    Start-Phase -Name "Findings"
    Update-Progress -Id $PROG_FINDINGS -Activity "Findings" -Status "Scanning scopes..." -PercentComplete 5
    if(-not $VulnData){ Write-Log "No data for findings." -Level WARN; Stop-Phase -Name "Findings"; Complete-Progress -Id $PROG_FINDINGS; return }

    $existing=@{}
    $files = Get-ChildItem -Path $Config.Folders.Scopes -Filter "CHG*.xlsx" -Recurse -ErrorAction SilentlyContinue
    foreach($sf in $files){
        try{
            $si = Get-ExcelSheetInfo -Path $sf.FullName | Where-Object { -not $_.Hidden } | Select-Object -First 1
            if($si){
                $d = Import-Excel -Path $sf.FullName -WorksheetName $si.Name
                foreach($row in $d){
                    $pluginId = $row.'definition.id'
                    if($pluginId){ $existing[$pluginId.ToString().Trim()] = $true }
                }
            }
        } catch { Write-Log "Scope parse failed $($sf.Name): $_" -Level WARN }
    }

    $byFam=@{}
    foreach($v in $VulnData){
        $pluginId=$v.'definition.id'; if(-not $pluginId){ continue }
        $key=$pluginId.ToString().Trim()
        if(-not $existing.ContainsKey($key)){
            $fam=Get-VulnerabilityFamily -VulnName $v.'definition.name'
            if(-not $byFam.ContainsKey($fam)){ $byFam[$fam]=@() }
            $byFam[$fam]+=$v
        }
    }

    $families=$byFam.Keys; $total=$families.Count; $i=0
    foreach($famKey in $families){
        $i++; Update-Progress -Id $PROG_FINDINGS -Activity "Findings" -Status "Generating: $famKey ($i of $total)" -PercentComplete ([int](($i/[double]$total)*100))
        if($byFam[$famKey].Count -gt 0){
            if($CreateMissingScopes){ Create-FamilyScopeIfMissing -Family $famKey -VulnDataForFamily $byFam[$famKey] }
            else { Generate-FindingsReport -Family $famKey -VulnData $byFam[$famKey] }
        }
    }

    Update-Progress -Id $PROG_FINDINGS -Activity "Findings" -Status "Done" -PercentComplete 100
    Stop-Phase -Name "Findings"; Complete-Progress -Id $PROG_FINDINGS -Activity "Findings"
}

# --- Helper to package functions into runspace (for parallel validations) ---
function Get-ValidationRunspaceBootstrap {
    $defs = @()
    $defs += ${function:NZ}.ToString()
    $defs += ${function:Write-Log}.ToString()
    $defs += ${function:Try-ParseDate}.ToString()
    $defs += ${function:Test-IPv4}.ToString()
    $defs += ${function:STrim}.ToString()
    $defs += ${function:Add-Audit}.ToString()
    $defs += ${function:Match-VulnByPriority}.ToString()
    $defs += ${function:Open-ExcelPackageWithRetry}.ToString()
    $defs += ${function:Run-SingleScopeValidation}.ToString()
    $defs -join "`n`n"
}

function Run-ScopeValidations { param([array]$VulnData)
    Start-Phase -Name "Validations"
    Update-Progress -Id $PROG_VALIDATIONS -Activity "Scope Validations" -Status "Building lookup..." -PercentComplete 5
    if(-not $VulnData){ Write-Log "No data for validations." -Level WARN; Stop-Phase -Name "Validations"; Complete-Progress -Id $PROG_VALIDATIONS; return }

    $vulnLookup = Build-ValidationLookup -VulnData $VulnData
    $totalKeys = ($vulnLookup.NETBIOS.Count + $vulnLookup.IP.Count + $vulnLookup.NAME.Count + $vulnLookup.FQDN.Count)
    Write-Log "Built validation lookup: $totalKeys keys (NETBIOS=$($vulnLookup.NETBIOS.Count), IP=$($vulnLookup.IP.Count), NAME=$($vulnLookup.NAME.Count), FQDN=$($vulnLookup.FQDN.Count))"

    $all = Get-ChildItem -Path $Config.Folders.Scopes -Filter "CHG*.xlsx" -Recurse -ErrorAction SilentlyContinue |
           Sort-Object Length, LastWriteTime  # small/quick scopes first
    $files = if($ValidationMaxFiles -gt 0){ $all | Select-Object -First $ValidationMaxFiles } else { $all }
    $total=($files|Measure-Object).Count
    if($total -eq 0){
        Write-Log "No scope files found to validate." -Level WARN
        Stop-Phase -Name "Validations"; Complete-Progress -Id $PROG_VALIDATIONS -Activity "Scope Validations"
        return
    }

    if(-not $Config.Performance.ValidationParallel){
        # ---- serial fallback ----
        $i=0
        foreach($sf in $files){
            $i++; Update-Progress -Id $PROG_VALIDATIONS -Activity "Scope Validations" -Status "Validating $($sf.Name) ($i of $total)" -PercentComplete ([int](($i/[double]$total)*100)) -CurrentOperation $sf.FullName
            try{ Run-SingleScopeValidation -ScopeFile $sf.FullName -VulnLookup $vulnLookup } catch { Write-Log "Scope validation failed $($sf.Name): $_" -Level ERROR }
        }
    } else {
        # ---- parallel using runspace pool ----
        $deg = [Math]::Max(1,[Math]::Min(8,[int]$Config.Performance.ValidationDegree))
        if($deg -lt 2){ $deg = 2 }
        if($deg -gt 4){ $deg = 4 } # keep modest to avoid I/O thrash

        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $pool = [runspacefactory]::CreateRunspacePool(1,$deg,$iss,$Host)
        $pool.Open()
        $bootstrap = Get-ValidationRunspaceBootstrap

        $jobs = @()
        foreach($sf in $files){
            $ps = [powershell]::Create()
            $null = $ps.AddScript({
                param($scopeFile, $lookup, $config, $fast, $skipFormatting, $bootstrapCode)
                Import-Module ImportExcel -DisableNameChecking
                try { Add-Type -AssemblyName System.Drawing } catch {}
                # load function defs into this runspace
                Invoke-Expression $bootstrapCode
                # inject settings/flags expected by the functions
                $Config = $config
                $FastMode = $fast
                $SkipFormatting = $skipFormatting
                if(-not $script:Audit){ $script:Audit = New-Object System.Collections.ArrayList }
                if($null -eq $script:AmbiguityLogs){ $script:AmbiguityLogs = 0 }
                if($null -eq $script:AmbiguityTotal){ $script:AmbiguityTotal = 0 }
                # run
                Run-SingleScopeValidation -ScopeFile $scopeFile -VulnLookup $lookup
            }).AddArgument($sf.FullName).AddArgument($vulnLookup).AddArgument($Config).AddArgument($FastMode).AddArgument($SkipFormatting).AddArgument($bootstrap)

            $ps.RunspacePool = $pool
            $handle = $ps.BeginInvoke()
            $jobs += [pscustomobject]@{ PS=$ps; Handle=$handle; File=$sf.FullName; Name=$sf.Name }
        }

        $completed = 0
        while($completed -lt $jobs.Count){
            foreach($j in ($jobs | Where-Object { -not $_.Handle.IsCompleted })){
                if($j.Handle.IsCompleted){
                    try { $j.PS.EndInvoke($j.Handle) | Out-Null } catch { Write-Log "Scope validation failed $($j.Name): $_" -Level ERROR }
                    finally { $j.PS.Dispose() }
                    $completed++
                    Update-Progress -Id $PROG_VALIDATIONS -Activity "Scope Validations" -Status "Completed $completed of $total" -PercentComplete ([int](($completed/[double]$total)*100))
                }
            }
            Start-Sleep -Milliseconds 200
        }

        $pool.Close(); $pool.Dispose()
    }

    Update-Progress -Id $PROG_VALIDATIONS -Activity "Scope Validations" -Status "Done" -PercentComplete 100
    Stop-Phase -Name "Validations"; Complete-Progress -Id $PROG_VALIDATIONS -Activity "Scope Validations"
}

function Run-SingleScopeValidation { param([string]$ScopeFile,[hashtable]$VulnLookup)
    $scopeName=[IO.Path]::GetFileNameWithoutExtension($ScopeFile)
    Write-Log "Validating scope: $scopeName"
    try{
        $si = Get-ExcelSheetInfo -Path $ScopeFile | Where-Object { -not $_.Hidden } | Select-Object -First 1
        if(-not $si){ throw "No visible worksheets" }
        $scopeData = Import-Excel -Path $ScopeFile -WorksheetName $si.Name
        if(-not $scopeData -or $scopeData.Count -eq 0){ throw "Scope contains no data" }

        $h=@{}; foreach($n in $scopeData[0].PSObject.Properties.Name){ $h[($n.ToLower() -replace '[^a-z0-9]','')]=$n }
        $assetCol=$null; foreach($k in @('assetnetbiosname','netbios','assetname','assetdisplayipv4address','ipv4','hostname','fqdn')){ if($h.ContainsKey($k)){ $assetCol=$h[$k]; break } }
        $pluginCol=$null; foreach($k in @('definitionid','pluginid')){ if($h.ContainsKey($k)){ $pluginCol=$h[$k]; break } }
        $sheetLastSeenCol = $null
        foreach($n in $scopeData[0].PSObject.Properties.Name){ if($n -eq 'Current Last Seen' -or $n -eq 'Last Seen'){ $sheetLastSeenCol = $n; break } }
        if(-not $assetCol -or -not $pluginCol){ throw "Could not identify Asset/Plugin columns" }

        $results=@(); $outstanding=0; $remediated=0; $notfound=0
        $threshold = (Get-Date).AddDays(-30)

        foreach($row in $scopeData){
            $asset=($row.$assetCol -as [string]); $pluginId=($row.$pluginCol -as [string])
            if([string]::IsNullOrWhiteSpace($asset) -or [string]::IsNullOrWhiteSpace($pluginId)){ continue }
            $plugKey=$pluginId.Trim().ToUpperInvariant()

            $validated = $row.PSObject.Copy()
            foreach($extra in @('Validation Results','Current State','Current Last Seen')){ if(-not ($validated.PSObject.Properties.Name -contains $extra)){ $validated | Add-Member -NotePropertyName $extra -NotePropertyValue '' -Force } }

            $match = Match-VulnByPriority -AssetText $asset -PluginId $plugKey -Lookup $VulnLookup -ScopeName $scopeName

            $sheetLS = $null
            if($sheetLastSeenCol){ $sheetLS = Try-ParseDate -Text ($row.$sheetLastSeenCol -as [string]) }

            if($match){
                $state=($match.state -as [string])
                $csvLS = Try-ParseDate -Text ($match.last_seen -as [string])
                $effectiveLS = if($Config.Quality.PreferSheetLastSeen -and $sheetLS){ $sheetLS } else { if($csvLS){ $csvLS } else { $sheetLS } }

                if($effectiveLS -ne $null -and $effectiveLS -lt $threshold){
                    $validated.'Validation Results'='Remediated'
                    $validated.'Current State' = 'Last Seen > 30 days'
                    $validated.'Current Last Seen' = ($effectiveLS.ToString('yyyy-MM-dd'))
                    $remediated++
                }
                elseif($state -match '(?i)fix|remediated|resolved|closed'){
                    $validated.'Validation Results'='Remediated'
                    $validated.'Current State' = (NZ $state 'Unknown')
                    $validated.'Current Last Seen' = (if($csvLS){ $csvLS.ToString('yyyy-MM-dd') } elseif($sheetLS){ $sheetLS.ToString('yyyy-MM-dd') } else { 'Unknown' })
                    $remediated++
                } else {
                    $validated.'Validation Results'='Outstanding'
                    $validated.'Current State' = (NZ $state 'Unknown')
                    $validated.'Current Last Seen' = (if($csvLS){ $csvLS.ToString('yyyy-MM-dd') } elseif($sheetLS){ $sheetLS.ToString('yyyy-MM-dd') } else { 'Unknown' })
                    $outstanding++
                }
            } else {
                $validated.'Validation Results'='Remediated'
                $validated.'Current State'='Not Found'
                $validated.'Current Last Seen' = (if($sheetLS){ $sheetLS.ToString('yyyy-MM-dd') } else { 'Not Found' })
                $remediated++; $notfound++
            }
            $results += $validated
        }

        $date=Get-Date -Format "yyyy-MM-dd"
        $fileName="$date Validation - $scopeName.xlsx"
        if($outstanding -eq 0 -and $remediated -eq 0){ $fileName=$fileName -replace '\.xlsx$',' - ERRORS.xlsx' }
        elseif($outstanding -eq 0 -and $remediated -gt 0){ $fileName=$fileName -replace '\.xlsx$',' - RESOLVED.xlsx' }
        elseif($outstanding -gt 0){
            $uniqueOut = ($results | Where-Object { $_.'Validation Results' -eq 'Outstanding' } | Select-Object -ExpandProperty $assetCol -Unique).Count
            $fileName=$fileName -replace '\.xlsx$',(" - OUTSTANDING {0}.xlsx" -f $uniqueOut)
        }

        $outFolder = Join-Path $Config.Folders.Validation "Reports"
        if(-not (Test-Path $outFolder)){ New-Item -Path $outFolder -ItemType Directory -Force | Out-Null }
        $outPath = Join-Path $outFolder $fileName

        $sorted = $results | Sort-Object @{Expression={ switch($_.'Validation Results'){ 'Outstanding'{0};'Remediated'{1}; default{2} } } }
        if(-not $FastMode -and $Config.Performance.EnableAutoSize -and -not $SkipFormatting){ $sorted | Export-Excel -Path $outPath -WorksheetName $si.Name -AutoFilter -AutoSize -NoNumberConversion }
        else { $sorted | Export-Excel -Path $outPath -WorksheetName $si.Name -AutoFilter -NoNumberConversion }

        try{
            $p = Open-ExcelPackageWithRetry -Path $outPath
            $ws=$p.Workbook.Worksheets[$si.Name]
            if(-not $FastMode -and -not $SkipFormatting){
                if($ws -and $ws.Dimension){
                    $ws.Cells[1,1,1,$ws.Dimension.End.Column].Style.Font.Bold=$true
                    $ws.Cells[1,1,1,$ws.Dimension.End.Column].AutoFilter=$true
                    $colIdx=$null; for($c=1;$c -le $ws.Dimension.End.Column;$c++){ if($ws.Cells[1,$c].Text -eq 'Validation Results'){ $colIdx=$c; break } }
                    if($colIdx){
                        $rng=$ws.Cells[2,$colIdx,$ws.Dimension.End.Row,$colIdx]
                        $fmt1=$ws.ConditionalFormatting.AddEqual($rng); $fmt1.Formula='"Outstanding"'; $fmt1.Style.Font.Color.Color=[System.Drawing.Color]::DarkRed
                        $fmt2=$ws.ConditionalFormatting.AddEqual($rng); $fmt2.Formula='"Remediated"';  $fmt2.Style.Font.Color.Color=[System.Drawing.Color]::DarkGreen
                    }
                    if($Config.Performance.EnableAutoSize){ $ws.Cells.AutoFitColumns() }
                }
            }
            # ensure/keep Summary hidden
            $sum=$p.Workbook.Worksheets['Summary']
            if($sum -and $sum.Hidden -ne [OfficeOpenXml.eWorkSheetHidden]::Hidden){
                $sum.Hidden = [OfficeOpenXml.eWorkSheetHidden]::Hidden
            }
            $p.Save(); $p.Dispose()
        } catch { try{ if($p){ $p.Dispose() } }catch{} }

        Write-Log "Validation complete: OUT=$outstanding, REM=$remediated, NF=$notfound" -Level SUCCESS
        Write-Log "Validation report: $outPath" -Level SUCCESS
    } catch { Write-Log "Validation failed ($scopeName): $_" -Level ERROR; throw }
}

# ================================================================================
# DASHBOARD / ARCHIVE / IDEMPOTENCY / NOTES / CHG monitor / MAIN
# ================================================================================
function Build-TrendFromWeeklyReports { param([string[]]$ReportTypes)
    $trend=@{}
    foreach($rt in $ReportTypes){
        if(-not $Config.Reports.ContainsKey($rt)){ continue }
        $rc=$Config.Reports[$rt]; $path=Get-LatestReportFile -Folder $Config.Folders.WeeklyReports -Patterns $rc.ReportPatterns
        if(-not $path){ continue }
        try{
            $pkg=Open-ExcelPackageWithRetry -Path $path; $ws=$pkg.Workbook.Worksheets['Vulnerability Data']; if(-not $ws -or -not $ws.Dimension){ $pkg.Dispose(); continue }
            $col=@{}; for($c=1;$c -le $ws.Dimension.End.Column;$c++){ $h=($ws.Cells[1,$c].Text).Trim(); if($h){ $col[$h]=$c } }
            $sevCol=$col['Severity']; if(-not $sevCol){ $pkg.Dispose(); continue }

            $weekCols=@()
            for($c=1;$c -le $ws.Dimension.End.Column;$c++){ $hdr=($ws.Cells[1,$c].Text).Trim(); if($hdr -match '^\d{1,2}/\d{1,2}(/\d{2,4})?$'){ $weekCols += @{Header=$hdr;Col=$c} } }
            if(-not $weekCols){ $pkg.Dispose(); continue }

            $weeks=$weekCols.Header
            $crit=New-Object int[] ($weeks.Count); $high=New-Object int[] ($weeks.Count); $med=New-Object int[] ($weeks.Count)

            for($r=2;$r -le $ws.Dimension.End.Row;$r++){
                $sev=($ws.Cells[$r,$sevCol].Text).Trim().ToLower()
                for($i=0;$i -lt $weekCols.Count;$i++){
                    $raw=($ws.Cells[$r,$weekCols[$i].Col].Text).Trim(); $tmp=0; $val=0
                    if([int]::TryParse($raw,[ref]$tmp) -and $tmp -gt 0){ $val=1 }
                    switch($sev){ 'critical'{$crit[$i]+=$val} 'high'{$high[$i]+=$val} 'medium'{$med[$i]+=$val} }
                }
            }
            $trend[$rc.Category]=@{ Weeks=$weeks; Critical=$crit; High=$high; Medium=$med }
            $pkg.Dispose()
        } catch { try{ if($pkg){ $pkg.Dispose() } }catch{}; Write-Log "Trend failed for ${rt}: $_" -Level WARN }
    }
    $trend
}
function Generate-DashboardFeed { param([array]$VulnData)
    if(-not $GenerateDashboard){ return }
    Start-Phase -Name "Dashboard"
    Update-Progress -Id $PROG_DASHBOARD -Activity "Dashboard Feed" -Status "Aggregating..." -PercentComplete 5
    try{
        $sev=@{Critical=0;High=0;Medium=0}
        $groups = $VulnData | Group-Object 'definition.id'
        foreach($g in $groups){
            $s=($g.Group[0].severity -as [string])
            if($s -match '^(?i)critical$'){ $sev.Critical++ }
            elseif($s -match '^(?i)high$'){ $sev.High++ }
            elseif($s -match '^(?i)medium$'){ $sev.Medium++ }
        }
        $pending=0; if(Test-Path $Config.Folders.PendingCR){ $pending=(Get-ChildItem -Path $Config.Folders.PendingCR -File -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count }
        $activeInfo = Get-ActiveCHGSetAndMeta
        $scopes = ($activeInfo.Set.Keys | Measure-Object).Count

        $dash=@{
            GeneratedDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            WeekDate = $WeekDate
            Totals = @{ TotalScopes=$scopes; TotalPendingCRs=$pending; SeverityCounts=$sev }
        }
        $trend = Build-TrendFromWeeklyReports -ReportTypes $ReportTypes
        if($trend.Keys.Count -gt 0){ $dash.TrendByCategory=$trend }

        $json1 = Join-Path $Config.Folders.DashboardFeed "Dashboard_Feed.json"
        $dash | ConvertTo-Json -Depth 10 | Set-Content -Path $json1 -Encoding UTF8

        $trendV2=@()
        foreach($cat in $trend.Keys){
            $t=$trend[$cat]
            $trendV2 += @{ category=$cat; weeks=@($t.Weeks); critical=@($t.Critical); high=@($t.High); medium=@($t.Medium) }
        }
        $dash2=@{
            generatedAt=(Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            weekDate=$WeekDate
            totals=@{
                scopes=$scopes
                pendingCRs=$pending
                severity=@(@{label='Critical';count=$sev.Critical},@{label='High';count=$sev.High},@{label='Medium';count=$sev.Medium})
            }
            trends=$trendV2
        }
        $json2 = Join-Path $Config.Folders.DashboardFeed "dashboard.v2.json"
        $dash2 | ConvertTo-Json -Depth 6 | Set-Content -Path $json2 -Encoding UTF8

        Update-Progress -Id $PROG_DASHBOARD -Activity "Dashboard Feed" -Status "Done" -PercentComplete 100
        Write-Log "Dashboard feeds: $json1 | $json2" -Level SUCCESS
    } catch { Write-Log "Dashboard failed: $_" -Level ERROR }
    finally { Stop-Phase -Name "Dashboard"; Complete-Progress -Id $PROG_DASHBOARD -Activity "Dashboard Feed" }
}
function Archive-TenableCSV { param([string]$CsvPath)
    Start-Phase -Name "Archive"
    Update-Progress -Id $PROG_ARCHIVE -Activity "Archiving CSV" -Status "Preparing..." -PercentComplete 5
    try{
        $file=[IO.Path]::GetFileName($CsvPath); $yr=(Get-Date).Year; $mo=(Get-Date).ToString("MM")
        $arc=Join-Path $Config.Folders.TenableProcessed ("{0}\{1}" -f $yr,$mo)
        if(-not (Test-Path $arc)){ New-Item -Path $arc -ItemType Directory -Force | Out-Null }
        $dest=Join-Path $arc $file
        if(Test-Path $dest){ $name=[IO.Path]::GetFileNameWithoutExtension($file); $ext=[IO.Path]::GetExtension($file); $dest=Join-Path $arc ("{0}_{1}{2}" -f $name,(Get-Date -Format 'yyyyMMdd_HHmmss'),$ext) }

        $dl=Join-Path $env:USERPROFILE "Downloads"
        $fromDL = $CsvPath -like (Join-Path $dl "*")
        $fromInbound = $CsvPath -like (Join-Path $Config.Folders.TenableInbound "*")
        if($fromDL){ Copy-Item -Path $CsvPath -Destination $dest -Force; Write-Log "Copied CSV from Downloads to: $dest" -Level SUCCESS }
        elseif($fromInbound){ Move-Item -Path $CsvPath -Destination $dest -Force; Write-Log "Moved CSV from Inbound to: $dest" -Level SUCCESS }
        else{ Copy-Item -Path $CsvPath -Destination $dest -Force; Write-Log "Archived CSV to: $dest" -Level SUCCESS }

        if($Config.Tenable.KeepLatestCopy -and $Config.Tenable.LatestCopyPath){ try{ Copy-Item -Path $dest -Destination $Config.Tenable.LatestCopyPath -Force } catch {} }
        Update-Progress -Id $PROG_ARCHIVE -Activity "Archiving CSV" -Status "Done" -PercentComplete 100
    } catch { Write-Log "Archive failed: $_" -Level WARN }
    finally { Stop-Phase -Name "Archive"; Complete-Progress -Id $PROG_ARCHIVE -Activity "Archiving CSV" }
}
function Test-ProcessingIdempotency { param([string]$CsvPath,[switch]$Force)
    if($Force){ $hf=Join-Path $Config.Folders.Logs "last_processed_hash.txt"; if(Test-Path $hf){ try{ Remove-Item -Path $hf -Force }catch{} }; return $true }
    if([string]::IsNullOrWhiteSpace($CsvPath) -or -not (Test-Path $CsvPath)){ return $true }
    $hash=Get-FileHash -Path $CsvPath -Algorithm SHA256
    $hf=Join-Path $Config.Folders.Logs "last_processed_hash.txt"
    if(Test-Path $hf){
        $last=(Get-Content -Path $hf -Raw).Trim()
        if($last -eq $hash.Hash){ Write-Log "CSV already processed (hash match). Use -ForceReprocess to re-run." -Level WARN; return $false }
    }
    $hash.Hash | Set-Content -Path $hf -Encoding UTF8
    $true
}

# Lifecycle notes
function Get-WeeksSinceDiscovery { param([string]$MitigationPlan,[string]$CurrentWeek)
    if([string]::IsNullOrWhiteSpace($MitigationPlan)){ return 0 }
    $lines=$MitigationPlan -split "`n"
    $disc=$lines | Where-Object { $_ -match "discovered" -and $_ -match "\d+/\d+" } | Select-Object -Last 1
    if($disc -and ($disc -match "(\d+/\d+)")){ return [Math]::Min($lines.Count,8) }
    1
}
function Get-VulnerabilityLifecycleNote { param([int]$WeeksSinceDiscovery,[string]$CurrentWeek)
    if($WeeksSinceDiscovery -eq 1){ "Vulnerabilities discovered" }
    elseif($WeeksSinceDiscovery -eq 2){ "Latest findings submitted" }
    elseif($WeeksSinceDiscovery -eq 3){ "IT Gov will research these vulnerabilities further" }
    elseif($WeeksSinceDiscovery -ge 4){ "SLA Overdue. Needs escalation" }
    else { "Follow-up on findings" }
}
function Add-MitigationNote { param([string]$ExistingPlan,[string]$NewNote,[string]$Date)
    $prefix="$Date - "
    $line="$prefix$NewNote"
    if([string]::IsNullOrWhiteSpace($ExistingPlan)){ $line } else { "$line`n$ExistingPlan" }
}

# CHG approvals + tracking
function Monitor-CHGApprovals {
    Write-Log "Monitoring CHG approvals..." -Level STEP
    try{
        $folders=@( (Join-Path $Config.Folders.PendingCR "Workstations"), (Join-Path $Config.Folders.PendingCR "MS Servers"), (Join-Path $Config.Folders.PendingCR "Non-MS Servers") )
        foreach($folder in $folders){
            if(-not (Test-Path $folder)){ continue }
            $files=Get-ChildItem -Path $folder -Filter "*.xlsx" -File -ErrorAction SilentlyContinue
            foreach($file in $files){
                if($file.Name -match '\bCHG(\d{4,9})\b'){
                    $chg="CHG$($matches[1])"; $category=Split-Path $folder -Leaf
                    $scopesFolder = Join-Path $Config.Folders.Scopes $category
                    if(-not (Test-Path $scopesFolder)){ New-Item -Path $scopesFolder -ItemType Directory -Force | Out-Null }
                    $newPath = Join-Path $scopesFolder $file.Name
                    Move-Item -Path $file.FullName -Destination $newPath -Force
                    Write-Log "Moved approved CHG to Scopes: $chg" -Level SUCCESS
                    Update-CHGTracking -CHGNumber $chg -FilePath $newPath -Category $category
                }
            }
        }
    } catch { Write-Log "CHG monitor failed: $_" -Level ERROR }
}
function Update-CHGTracking { param([string]$CHGNumber,[string]$FilePath,[string]$Category)
    try{
        $master=Join-Path $Config.Folders.Scripts "CR_Master.xlsx"
        if(-not (Test-Path $master)){
            [PSCustomObject]@{ 'CHG ID'=''; 'Category'=''; 'Family Name'=''; 'Plugins Covered'=''; 'Scope Date'=''; 'Status'=''; 'File Path'='' } |
                Export-Excel -Path $master -WorksheetName "CHG Master" -AutoSize -NoNumberConversion
        }
        $si = Get-ExcelSheetInfo -Path $FilePath | Where-Object { -not $_.Hidden } | Select-Object -First 1
        $scopeData = if($si){ Import-Excel -Path $FilePath -WorksheetName $si.Name } else { @() }
        $plugins = if($scopeData){ ($scopeData | Select-Object -ExpandProperty 'definition.id' -Unique 2>$null) -join '; ' } else { "" }
        $fam = if($scopeData -and $scopeData.Count -gt 0){ Get-VulnerabilityFamily -VulnName $scopeData[0].'definition.name' } else { "Unknown" }
        $entry=[PSCustomObject]@{ 'CHG ID'=$CHGNumber; 'Category'=$Category; 'Family Name'=$fam; 'Plugins Covered'=$plugins; 'Scope Date'=(Get-Date -Format "yyyy-MM-dd"); 'Status'='Active'; 'File Path'=$FilePath }
        $existing=@(Import-Excel -Path $master -WorksheetName "CHG Master" 2>$null)
        ($existing + $entry) | Export-Excel -Path $master -WorksheetName "CHG Master" -ClearSheet -AutoSize -NoNumberConversion
        Write-Log "CHG tracking updated: $CHGNumber" -Level SUCCESS
    } catch { Write-Log "CHG tracking failed: $_" -Level WARN }
}

# MEMORY CLEANUP
function Invoke-MemoryCleanup {
    Write-Log "Performing memory cleanup..." -Level INFO
    [GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect()
}

# MAIN
function Main {
    $sw=[Diagnostics.Stopwatch]::StartNew()
    Update-Progress -Id $PROG_MAIN -Activity "Vulnerability Management Automation" -Status "Starting..." -PercentComplete 1
    try{
        Write-Log "Starting Vulnerability Management Automation" -Level STEP
        Write-Log "Week Date: $WeekDate"
        Write-Log "Report Types: $($ReportTypes -join ', ')"
        if($FastMode){ Write-Log "FAST MODE enabled (formatting minimized)." -Level WARN }

        Initialize-Environment

        Update-Progress -Id $PROG_MAIN -Activity "Vulnerability Management Automation" -Status "Locating Tenable CSV..." -PercentComplete 5
        $csv = Get-LatestTenableCSV
        if(-not (Test-ProcessingIdempotency -CsvPath $csv -Force:$ForceReprocess)){
            Update-Progress -Id $PROG_MAIN -Activity "Vulnerability Management Automation" -Status "Duplicate CSV (hash match) - exiting" -PercentComplete 100
            Complete-Progress -Id $PROG_MAIN -Activity "Vulnerability Management Automation"
            return
        }

        Update-Progress -Id $PROG_MAIN -Activity "Vulnerability Management Automation" -Status "Importing CSV..." -PercentComplete 15
        $data = Import-TenableCSV -CsvPath $csv

        # Build once, reuse everywhere
        Initialize-GlobalCaches -VulnData $data

        # Optional pre-split (currently not needed elsewhere but cheap)
        $null = Split-DataByCategory -VulnData $data | Out-Null

        Invoke-MemoryCleanup

        # 1) Quick deliverable first
        Update-Progress -Id $PROG_MAIN -Activity "Vulnerability Management Automation" -Status "Dashboard..." -PercentComplete 30
        Generate-DashboardFeed -VulnData $data

        # 2) New findings
        Update-Progress -Id $PROG_MAIN -Activity "Vulnerability Management Automation" -Status "Findings..." -PercentComplete 45
        Detect-NewFindings -VulnData $data

        # 3) Weekly reports
        Update-Progress -Id $PROG_MAIN -Activity "Vulnerability Management Automation" -Status "Weekly reports..." -PercentComplete 60
        Process-WeeklyReports -VulnData $data -WeekDate $WeekDate

        # 4) Validations (parallel if enabled)
        if(-not $SkipValidation){
            Update-Progress -Id $PROG_MAIN -Activity "Vulnerability Management Automation" -Status "Validations..." -PercentComplete 80
            Run-ScopeValidations -VulnData $data
        }
        Invoke-MemoryCleanup

        # Archive CSV at the end
        Update-Progress -Id $PROG_MAIN -Activity "Vulnerability Management Automation" -Status "Archiving CSV..." -PercentComplete 92
        Archive-TenableCSV -CsvPath $csv

        $sw.Stop()
        Update-Progress -Id $PROG_MAIN -Activity "Vulnerability Management Automation" -Status "Done" -PercentComplete 100
        Complete-Progress -Id $PROG_MAIN -Activity "Vulnerability Management Automation"
        Write-Log "Automation completed successfully" -Level SUCCESS
        Write-Log ("Processing time: {0:N2}s" -f $sw.Elapsed.TotalSeconds) -Level SUCCESS
        Write-Log "Processed $($data.Count) records" -Level SUCCESS

        if($script:InvalidIPFiltered -gt 0){ Write-Log ("Filtered invalid IPv4 strings during validation lookup: {0}" -f $script:InvalidIPFiltered) -Level WARN }
        if($script:AmbiguityTotal -gt $script:AmbiguityLogs){
            Write-Log ("Ambiguous matches encountered: {0} (logged {1}; cap {2})" -f $script:AmbiguityTotal,$script:AmbiguityLogs,$Config.Quality.AmbiguityLogLimit) -Level WARN
        }

        if($script:Audit.Count -gt 0){
            Write-Host "`n=== AUDIT CHANGES ===" -ForegroundColor Cyan
            $script:Audit | ForEach-Object { Write-Host $_ }
            Write-Host "=====================" -ForegroundColor Cyan
        }
    } catch {
        $sw.Stop()
        Update-Progress -Id $PROG_MAIN -Activity "Vulnerability Management Automation" -Status "FAILED" -PercentComplete 100
        Complete-Progress -Id $PROG_MAIN -Activity "Vulnerability Management Automation"
        Write-Log "CRITICAL ERROR: $_" -Level ERROR
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR
        throw
    }
}

function Monitor-And-Run {
    Write-Host "Initializing folder structure..." -ForegroundColor Cyan
    foreach($key in $Config.Folders.Keys){
        $folder=$Config.Folders[$key]
        if(-not (Test-Path $folder)){
            try{ New-Item -Path $folder -ItemType Directory -Force | Out-Null; Write-Host "Created folder: $folder" -ForegroundColor Green }
            catch{ Write-Host "CRITICAL ERROR: Cannot create folder $folder - $_" -ForegroundColor Red; exit 1 }
        }
    }
    $script:LogFile = Join-Path $Config.Folders.Logs ("VulnMgmt_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    Monitor-CHGApprovals
    Main
}

if ($MyInvocation.InvocationName -ne '.') { Monitor-And-Run }