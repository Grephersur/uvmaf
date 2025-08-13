# Fixed version of the script - showing key bug fixes

# BUG FIX 1: Config section - ValidationDegree
$Config = @{
    BasePath    = "C:\Lumen21"
    Performance = @{
        EnableAutoSize     = $false
        FastModeDefault    = $true
        ValidationParallel = $true
        ValidationDegree   = 3          # FIXED: Was $3, now 3
    }
}

# BUG FIX 2: Add-Audit function with auto-initialization
function Add-Audit { 
    param([string]$What,[string]$Detail) 
    if ($What){ 
        # FIXED: Auto-initialize $script:Audit if missing
        if(-not $script:Audit){ 
            $script:Audit = New-Object System.Collections.ArrayList 
        } 
        $null=$script:Audit.Add("$What | $Detail")
        Write-Log "AUDIT: $What :: $Detail" 
    } 
}

# BUG FIX 3: Create-FamilyScopeIfMissing function
function Create-FamilyScopeIfMissing { 
    param([string]$Family,[array]$VulnDataForFamily)  # FIXED: Removed stray ']'
    Add-Audit -What "CreateScopeStub" -Detail ("Family={0}; Plugins={1}" -f $Family, ($VulnDataForFamily.'definition.id' | Select-Object -Unique | Measure-Object | Select-Object -ExpandProperty Count))
    Generate-FindingsReport -Family $Family -VulnData $VulnDataForFamily
}

# BUG FIX 4: Get-ValidationRunspaceBootstrap with STrim and Add-Audit
function Get-ValidationRunspaceBootstrap {
    $defs = @()
    $defs += ${function:NZ}.ToString()
    $defs += ${function:Write-Log}.ToString()
    $defs += ${function:Try-ParseDate}.ToString()
    $defs += ${function:Test-IPv4}.ToString()
    $defs += ${function:STrim}.ToString()           # FIXED: Added STrim
    $defs += ${function:Add-Audit}.ToString()        # FIXED: Added Add-Audit
    $defs += ${function:Match-VulnByPriority}.ToString()
    $defs += ${function:Open-ExcelPackageWithRetry}.ToString()
    $defs += ${function:Run-SingleScopeValidation}.ToString()
    $defs -join "`n`n"
}
