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
# ================================================================================
$Config = @{
    BasePath    = "C:\Lumen21"
    Performance = @{
        EnableAutoSize   = $false
        FastModeDefault  = $true
        ValidationParallel = $true      # enable parallel validations (requires SSD recommended)
        ValidationDegree   = 3          # max parallel validations (2–3 is sensible)
        BatchSize         = 10000       # CSV processing batch size for memory management
        MaxMemoryMB       = 2048        # memory threshold for cleanup
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
$script:MemoryUsage = 0

try { Add-Type -AssemblyName System.Drawing | Out-Null } catch {}

function Write-Log {
    param([Parameter(Mandatory=$true)][string]$Message,[ValidateSet("INFO","WARN","ERROR","SUCCESS","STEP")][string]$Level="INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"
    $color = switch($Level){ "STEP"{"Cyan"}; "SUCCESS"{"Green"}; "WARN"{"Yellow"}; "ERROR"{"Red"}; default{"White"} }
    Write-Host $entry -ForegroundColor $color
    if ($script:LogFile -and (Test-Path (Split-Path -Path $script:LogFile -Parent))) { 
        try { Add-Content -Path $script:LogFile -Value $entry -Encoding UTF8 } catch {} 
    }
}

function Add-Audit { param([string]$What,[string]$Detail) 
    if ($What){ 
        $null=$script:Audit.Add("$What | $Detail"); 
        Write-Log "AUDIT: $What :: $Detail" 
    } 
}

function Start-Phase { 
    param([string]$Name) 
    $sw=[Diagnostics.Stopwatch]::StartNew(); 
    $script:Perf[$Name]=@{Stopwatch=$sw;Elapsed=[timespan]::Zero}; 
    Write-Log "▶ $Name" -Level STEP 
}

function Stop-Phase  { 
    param([string]$Name) 
    if($script:Perf.ContainsKey($Name)){
        $script:Perf[$Name].Stopwatch.Stop(); 
        $script:Perf[$Name].Elapsed=$script:Perf[$Name].Stopwatch.Elapsed; 
        Write-Log ("⏱ {0} took {1:N2}s" -f $Name,$script:Perf[$Name].Elapsed.TotalSeconds) 
    } 
}

function Update-Progress { 
    param([int]$Id,[string]$Activity,[string]$Status="",[int]$PercentComplete=0,[string]$CurrentOperation=$null) 
    if($NoProgress){return}; 
    try { 
        if($PSBoundParameters.ContainsKey('CurrentOperation')){
            Write-Progress -Id $Id -Activity $Activity -Status $Status -PercentComplete $PercentComplete -CurrentOperation $CurrentOperation
        }else{
            Write-Progress -Id $Id -Activity $Activity -Status $Status -PercentComplete $PercentComplete
        } 
    } catch {} 
}

function Complete-Progress { 
    param([int]$Id,[string]$Activity="") 
    if(-not $NoProgress){ 
        try { Write-Progress -Id $Id -Activity $Activity -Completed } catch {} 
    } 
}

function _UpperTrim([string]$s){ 
    if([string]::IsNullOrWhiteSpace($s)) { "" } else { $s.Trim().ToUpperInvariant() } 
}

# Universal safe-trim (prevents [System.Double].Trim crashes)
function STrim { 
    param($x)
    if($null -eq $x){ return "" }
    $s = $x -as [string]
    if([string]::IsNullOrWhiteSpace($s)){ return "" }
    return $s.Trim()
}

# Memory monitoring and cleanup
function Test-MemoryThreshold {
    $process = Get-Process -Id $PID
    $script:MemoryUsage = [math]::Round($process.WorkingSet64 / 1MB, 2)
    if($script:MemoryUsage -gt $Config.Performance.MaxMemoryMB) {
        Write-Log "Memory threshold exceeded: ${script:MemoryUsage}MB > $($Config.Performance.MaxMemoryMB)MB - triggering cleanup" -Level WARN
        Invoke-MemoryCleanup
        return $true
    }
    return $false
}

function Invoke-MemoryCleanup {
    Write-Log "Performing memory cleanup..." -Level INFO
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    [GC]::Collect()
    $process = Get-Process -Id $PID
    $script:MemoryUsage = [math]::Round($process.WorkingSet64 / 1MB, 2)
    Write-Log "Memory after cleanup: ${script:MemoryUsage}MB" -Level INFO
}

# Retry open (handles transient locks)
function Open-ExcelPackageWithRetry { 
    param([string]$Path,[int]$MaxAttempts=3,[int]$DelayMs=500)
    for($a=1;$a -le $MaxAttempts;$a++){
        try{ 
            return Open-ExcelPackage -Path $Path 
        } catch {
            if($a -ge $MaxAttempts){ throw }
            Start-Sleep -Milliseconds $DelayMs
        }
    }
}

# IPv4 validation
function Test-IPv4 { 
    param([string]$Text)
    if([string]::IsNullOrWhiteSpace($Text)){ return $false }
    $ip=$null
    if([System.Net.IPAddress]::TryParse($Text.Trim(),[ref]$ip)){
        return ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork)
    }
    return $false
}

# General helpers
function Ensure-NoteProperty { 
    param([psobject]$Obj,[string]$Name,[object]$Default=$null) 
    if(-not ($Obj.PSObject.Properties.Name -contains $Name)){ 
        $Obj | Add-Member -NotePropertyName $Name -NotePropertyValue $Default -Force 
    } 
}

function Get-WorksheetHeaders { 
    param([string]$Path,[string]$SheetName)
    $pkg = Open-ExcelPackageWithRetry -Path $Path
    try{
        $ws=$pkg.Workbook.Worksheets[$SheetName]; 
        if(-not $ws -or -not $ws.Dimension){ return @() }
        $out=@(); 
        for($c=1;$c -le $ws.Dimension.End.Column;$c++){ 
            $h=($ws.Cells[1,$c].Text).Trim(); 
            if($h){ $out+=$h } 
        }
        $out
    } finally { 
        if($pkg){ 
            try { $pkg.Dispose() } catch {} 
        } 
    }
}

function Insert-HeaderAfter { 
    param([string[]]$Headers,[string]$NewHeader,[string]$AfterHeader)
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

function Dedup-Headers { 
    param([string[]]$Headers)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $res=@()
    foreach($h in $Headers){
        if(-not $seen.Contains($h)){ 
            [void]$seen.Add($h); 
            $res+=$h 
        } else { 
            Write-Log "Duplicate header ignored in template: $h" -Level WARN 
        }
    }
    ,$res
}

# Caches
$script:AliasIndex        = $null
$script:PluginGroups      = $null
$script:PluginIdToFamily  = $null
$script:VulnLookup        = $null

$PROG_MAIN=1; $PROG_IMPORT=2; $PROG_WEEKLY=3; $PROG_FINDINGS=4; $PROG_VALIDATIONS=5; $PROG_ARCHIVE=6; $PROG_DASHBOARD=7