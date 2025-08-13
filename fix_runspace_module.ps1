# Correct way to add ImportExcel module to InitialSessionState in PowerShell 5.1

# INCORRECT (causes the error):
# $iss.Modules.Add((New-Object System.Management.Automation.Runspaces.SessionStateModuleEntry('ImportExcel')))

# CORRECT approaches:

# Option 1: Import the module into the runspace after creation
$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
# Don't add module to ISS, instead import it in the runspace script

# Option 2: Use ImportPSModule command
$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$iss.ImportPSModule('ImportExcel')

# Option 3: Add module path to ISS
$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$moduleInfo = Get-Module -ListAvailable -Name ImportExcel | Select-Object -First 1
if ($moduleInfo) {
    $iss.ImportPSModulesFromPath($moduleInfo.ModuleBase)
}