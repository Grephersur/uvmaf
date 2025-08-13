# Fixed Run-ScopeValidations function
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
        $deg = [Math]::Max(1,[int]$ValidationDegree)
        if($deg -gt 8){ $deg = 8 } # cap at 8 to avoid I/O thrash on most systems
        
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        # FIXED: Use ImportPSModule method instead of trying to create SessionStateModuleEntry
        try {
            $iss.ImportPSModule('ImportExcel')
        } catch {
            # Module will be imported in runspace if this fails
            Write-Log "Could not pre-import ImportExcel module into ISS, will import in runspace" -Level WARN
        }

        $pool = [runspacefactory]::CreateRunspacePool(1,$deg,$iss,$Host)
        $pool.Open()
        
        # Get the script block containing all necessary helper functions
        $bootstrapScript = Get-ValidationRunspaceBootstrap

        $jobs = @()
        foreach($sf in $files){
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            
            # 1. Load the helper functions into the runspace
            $null = $ps.AddScript($bootstrapScript)

            # 2. Add the main command and pass variables as parameters
            $null = $ps.AddScript({
                param($scopeFile, $lookup, $configParam, $fastModeParam, $skipFormattingParam)
                
                # Ensure ImportExcel is loaded in this runspace
                if (-not (Get-Module -Name ImportExcel)) {
                    try {
                        Import-Module ImportExcel -DisableNameChecking -ErrorAction Stop
                    } catch {
                        throw "Failed to import ImportExcel module in runspace: $_"
                    }
                }
                
                # Set variables required by the functions within the runspace
                $script:Config = $configParam
                $script:FastMode = $fastModeParam
                $script:SkipFormatting = $skipFormattingParam
                $script:NoProgress = $true # Progress bars don't work well in runspaces

                # Initialize script-scoped variables needed for auditing in the runspace
                $script:Audit = New-Object System.Collections.ArrayList
                $script:AmbiguityLogs = 0
                $script:AmbiguityTotal = 0
                
                Run-SingleScopeValidation -ScopeFile $scopeFile -VulnLookup $lookup
            }).AddArgument($sf.FullName).AddArgument($vulnLookup).AddArgument($Config).AddArgument($FastMode).AddArgument($SkipFormatting)
            
            $handle = $ps.BeginInvoke()
            $jobs += [pscustomobject]@{ PS=$ps; Handle=$handle; File=$sf.FullName; Name=$sf.Name }
        }

        $completed = 0
        while($completed -lt $jobs.Count){
            $waitHandles = $jobs.Handle | Select-Object -ExpandProperty AsyncWaitHandle
            [System.Threading.WaitHandle]::WaitAny($waitHandles, 200) | Out-Null

            foreach($j in ($jobs | Where-Object { $_.Handle.IsCompleted -and -not $_.Done })){
                try { 
                    $j.PS.EndInvoke($j.Handle) | Out-Null 
                } catch { 
                    Write-Log "Scope validation failed $($j.Name): $_" -Level ERROR 
                }
                finally { 
                    $j.PS.Dispose() 
                    $j.Done = $true
                }
                $completed++
                Update-Progress -Id $PROG_VALIDATIONS -Activity "Scope Validations" -Status "Completed $completed of $total" -PercentComplete ([int](($completed/[double]$total)*100))
            }
        }

        $pool.Close(); $pool.Dispose()
    }

    Update-Progress -Id $PROG_VALIDATIONS -Activity "Scope Validations" -Status "Done" -PercentComplete 100
    Stop-Phase -Name "Validations"; Complete-Progress -Id $PROG_VALIDATIONS -Activity "Scope Validations"
}
