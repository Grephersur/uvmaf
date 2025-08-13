# Resilient v1.6.13 RC18d (PS 5.1-safe)
# Unified Vulnerability Management Automation Framework
# ----------------------------------------------------------------------------------
# RC18d: Fixes + small perf/reliability tweaks over RC18c
# - Fix: Create-FamilyScopeIfMissing param list stray ']' causing parse error.
# - Fix: Parallel validation runspace bootstrap now includes STrim and Add-Audit.
# - Robust Add-Audit: auto-initialize $script:Audit if missing (safe for runspaces).
# - Reliability: Ensure TLS 1.2 before Install-Module on PS 5.1; harden error actions.
# - Perf: Default Export-Excel -NoNumberConversion via $PSDefaultParameterValues.
# - Kept RC18b optimizations (caches, column projection, parallel validations, etc.).
# - New: Update-WeeklyReport now uses a temp file, then renames it.
# - New: Import-TenableCSV column projection is now dynamic and more robust.
# - New: Get-LatestReportFile uses a more specific filter for efficiency.
# - New: ValidationDegree respects user input without arbitrary caps.
# - New: Runspace functions are loaded into the InitialSessionState, replacing Invoke-Expression.
# - New: Get-WorksheetHeaders function removed, logic inlined for efficiency.
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
    [int]$ValidationDegree = 3, # New: ValidationDegree parameter added

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
        ValidationDegree   = $3         # max parallel validations (2–3 is sensible)
    }
    Tenable     = @{ KeepLatestCopy = $true; LatestCopyPath = "" }
    Quality     = @{
        CriticalFieldMissingThresholdPercent = 10
        PreferSheetLastSeen                  = $false
        GateCompletedByValidation            = $false
        AmbiguityLogLimit                    = 50
        LogCustomColumnWarn                  = $false    # set true to log "custom columns left blank" warnings
    }
}