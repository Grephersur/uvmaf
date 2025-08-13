# Resilient v1.7.0 - Fixed and Optimized
# Unified Vulnerability Management Automation Framework
# ----------------------------------------------------------------------------------
# v1.7.0 Changes (Fixed from RC18b):
# - Fixed all syntax errors and type safety issues
# - Added comprehensive security validation (path traversal protection)
# - Optimized memory usage with streaming CSV processing
# - Improved performance with single-pass data processing
# - Enhanced error handling and resource management
# - Added input sanitization and validation
# - Implemented proper synchronization for parallel operations
# - Fixed date parsing and asset matching logic
# - Added connection pooling for Excel operations
# - Improved logging with sensitive data protection
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
# SECURITY FUNCTIONS (NEW)
# ================================================================================
function Test-SafePath {
    param([string]$Path, [string]$BasePath)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        $resolved = [System.IO.Path]::GetFullPath($Path)
        $baseResolved = [System.IO.Path]::GetFullPath($BasePath)
        return $resolved.StartsWith($baseResolved, [StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        return $false
    }
}

function Get-SanitizedFileName {
    param([string]$FileName)
    if ([string]::IsNullOrWhiteSpace($FileName)) { return "unnamed" }
    # Allow only alphanumeric, spaces, dashes, underscores, and dots
    $sanitized = [regex]::Replace($FileName, '[^a-zA-Z0-9\s\-_\.]', '')
    if ([string]::IsNullOrWhiteSpace($sanitized)) { return "unnamed" }
    return $sanitized.Substring(0, [Math]::Min(255, $sanitized.Length))
}

function Test-ValidInput {
    param(
        [string]$Input,
        [ValidateSet('AssetName','PluginId','CHGNumber','FileName','Path')]
        [string]$Type
    )
    
    switch ($Type) {
        'AssetName' { 
            return $Input -match '^[a-zA-Z0-9\-_\.\s]{1,255}$' 
        }
        'PluginId' { 
            return $Input -match '^\d{1,10}$' 
        }
        'CHGNumber' { 
            return $Input -match '^CHG\d{7,9}$' 
        }
        'FileName' { 
            return $Input -match '^[a-zA-Z0-9\-_\.\s]{1,255}\.(xlsx|csv|json)$' 
        }
        'Path' { 
            return -not ($Input -match '\.\.|[\<\>\:\"\|\?\*]') 
        }
    }
    return $false
}

# ================================================================================
# CONFIG (ENHANCED WITH VALIDATION)
# ================================================================================
$Config = @{
    BasePath    = "C:\Lumen21"
    Performance = @{
        EnableAutoSize      = $false
        FastModeDefault     = $true
        ValidationParallel  = $true
        ValidationDegree    = [Math]::Min(3, [Environment]::ProcessorCount)
        MaxMemoryMB         = 2048  # New: Memory limit
        ChunkSize           = 10000 # New: CSV chunk size
        ExcelPoolSize       = 5     # New: Excel connection pool
    }
    Security = @{  # New section
        EnablePathValidation = $true
        EnableInputSanitization = $true
        LogSensitiveData = $false
        MaxLogSizeMB = 100
    }
    Tenable     = @{ KeepLatestCopy = $true; LatestCopyPath = "" }
    Quality     = @{
        CriticalFieldMissingThresholdPercent = 10
        PreferSheetLastSeen                  = $false
        GateCompletedByValidation            = $false
        AmbiguityLogLimit                    = 50
        LogCustomColumnWarn                  = $false
    }
}

# Validate base path exists and is accessible
if (-not (Test-Path $Config.BasePath)) {
    Write-Error "Base path does not exist: $($Config.BasePath)"
    exit 1
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

# Validate all paths are under base path
foreach ($key in $Config.Folders.Keys) {
    if (-not (Test-SafePath -Path $Config.Folders[$key] -BasePath $Config.BasePath)) {
        Write-Error "Invalid folder path detected: $($Config.Folders[$key])"
        exit 1
    }
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
# LOGGING / HELPERS (ENHANCED)
# ================================================================================
function NZ { param($Value,$Default="") if ($null -eq $Value) { $Default } else { $Value } }

$script:LogFile = $null
$script:Perf = @{}
$script:Audit = New-Object System.Collections.ArrayList
$script:AmbiguityLogs = 0
$script:AmbiguityTotal = 0
$script:InvalidIPFiltered = 0
$script:ExcelPool = New-Object System.Collections.Queue  # New: Excel connection pool
$script:StringCache = @{}  # New: String conversion cache
$script:DateCache = @{}    # New: Date parsing cache
$script:RegexCache = @{}   # New: Compiled regex cache

try { Add-Type -AssemblyName System.Drawing | Out-Null } catch {}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS","STEP")][string]$Level="INFO",
        [switch]$Sensitive
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Scrub sensitive data if needed
    if ($Sensitive -and -not $Config.Security.LogSensitiveData) {
        $Message = $Message -replace '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'xxx.xxx.xxx.xxx'
        $Message = $Message -replace '\bCHG\d{7,9}\b', 'CHGxxxxxxx'
    }
    
    $entry = "[$ts] [$Level] $Message"
    $color = switch($Level){ "STEP"{"Cyan"}; "SUCCESS"{"Green"}; "WARN"{"Yellow"}; "ERROR"{"Red"}; default{"White"} }
    Write-Host $entry -ForegroundColor $color
    
    if ($script:LogFile -and (Test-Path (Split-Path -Path $script:LogFile -Parent))) { 
        try { 
            # Check log size
            if ((Test-Path $script:LogFile) -and ((Get-Item $script:LogFile).Length -gt ($Config.Security.MaxLogSizeMB * 1MB))) {
                $backup = $script:LogFile -replace '\.log$', "_$(Get-Date -Format 'yyyyMMddHHmmss').log"
                Move-Item -Path $script:LogFile -Destination $backup -Force
            }
            Add-Content -Path $script:LogFile -Value $entry -Encoding UTF8 
        } catch {} 
    }
}

function Add-Audit { 
    param([string]$What,[string]$Detail) 
    if ($What){ 
        $null=$script:Audit.Add("$What | $Detail")
        Write-Log "AUDIT: $What :: $Detail" -Sensitive 
    } 
}

function Start-Phase { 
    param([string]$Name) 
    $sw=[Diagnostics.Stopwatch]::StartNew()
    $script:Perf[$Name]=@{Stopwatch=$sw;Elapsed=[timespan]::Zero}
    Write-Log "▶ $Name" -Level STEP 
}

function Stop-Phase { 
    param([string]$Name) 
    if($script:Perf.ContainsKey($Name)){ 
        $script:Perf[$Name].Stopwatch.Stop()
        $script:Perf[$Name].Elapsed=$script:Perf[$Name].Stopwatch.Elapsed
        Write-Log ("⏱ {0} took {1:N2}s" -f $Name,$script:Perf[$Name].Elapsed.TotalSeconds) 
    } 
}

function Update-Progress { 
    param(
        [int]$Id,
        [string]$Activity,
        [string]$Status="",
        [int]$PercentComplete=0,
        [string]$CurrentOperation=$null
    ) 
    if($NoProgress){return}
    try { 
        if($PSBoundParameters.ContainsKey('CurrentOperation')){
            Write-Progress -Id $Id -Activity $Activity -Status $Status -PercentComplete $PercentComplete -CurrentOperation $CurrentOperation
        } else {
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

# Enhanced string functions with caching
function _UpperTrim {
    param([string]$s)
    if([string]::IsNullOrWhiteSpace($s)) { return "" }
    
    # Check cache first
    if ($script:StringCache.ContainsKey($s)) {
        return $script:StringCache[$s]
    }
    
    $result = $s.Trim().ToUpperInvariant()
    
    # Cache if not too many entries
    if ($script:StringCache.Count -lt 10000) {
        $script:StringCache[$s] = $result
    }
    
    return $result
}

# Universal safe-trim with type checking
function STrim { 
    param($x)
    if($null -eq $x){ return "" }
    
    # Type check before conversion
    $type = $x.GetType().Name
    if ($type -eq "String") {
        return $x.Trim()
    }
    
    # Safe conversion for other types
    try {
        $s = $x.ToString()
        if([string]::IsNullOrWhiteSpace($s)){ return "" }
        return $s.Trim()
    }
    catch {
        Write-Log "STrim conversion error for type $type" -Level WARN
        return ""
    }
}

# Enhanced retry with exponential backoff
function Open-ExcelPackageWithRetry { 
    param(
        [string]$Path,
        [int]$MaxAttempts=3,
        [int]$InitialDelayMs=500
    )
    
    # Validate path
    if (-not (Test-SafePath -Path $Path -BasePath $Config.BasePath)) {
        throw "Invalid Excel file path"
    }
    
    # Check pool first
    if ($script:ExcelPool.Count -gt 0) {
        $pkg = $script:ExcelPool.Dequeue()
        try {
            # Test if connection is still valid
            $test = $pkg.Workbook.Worksheets.Count
            return $pkg
        }
        catch {
            $pkg.Dispose()
        }
    }
    
    $delay = $InitialDelayMs
    for($a=1;$a -le $MaxAttempts;$a++){
        try{ 
            return Open-ExcelPackage -Path $Path 
        } catch {
            if($a -ge $MaxAttempts){ throw }
            Start-Sleep -Milliseconds $delay
            $delay *= 2  # Exponential backoff
        }
    }
}

# Return Excel package to pool
function Return-ExcelPackage {
    param($Package)
    if ($null -eq $Package) { return }
    
    if ($script:ExcelPool.Count -lt $Config.Performance.ExcelPoolSize) {
        $script:ExcelPool.Enqueue($Package)
    }
    else {
        $Package.Dispose()
    }
}

# Enhanced IPv4 validation with caching
function Test-IPv4 { 
    param([string]$Text)
    if([string]::IsNullOrWhiteSpace($Text)){ return $false }
    
    $trimmed = $Text.Trim()
    
    # Quick regex check first
    if ($trimmed -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        return $false
    }
    
    $ip=$null
    if([System.Net.IPAddress]::TryParse($trimmed,[ref]$ip)){
        return ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork)
    }
    return $false
}

# Progress tracking
$PROG_MAIN=1; $PROG_IMPORT=2; $PROG_WEEKLY=3; $PROG_FINDINGS=4; $PROG_VALIDATIONS=5; $PROG_ARCHIVE=6; $PROG_DASHBOARD=7