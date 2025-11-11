# This script is part of evil-winrm-py project https://github.com/adityatelange/evil-winrm-py
# It loads a dll in memory as a PowerShell module from a Base64 string and lists its exported functions.

# --- Define Parameters ---
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Base64Dll # Base64 encoded dll content
)

# --- Decode Base64 and Load Assembly ---
$dllBytes = [System.Convert]::FromBase64String($Base64Dll)
$assembly = [System.Reflection.Assembly]::Load($dllBytes)

# --- Output Assembly Metadata ---
$assemblyName = $assembly.GetName().Name
[PSCustomObject]@{
    Type = "Metadata"
    Name = $assemblyName
} | ConvertTo-Json -Compress | Write-Output

# --- Import Modules from the Assembly ---
try {
    Import-Module -Assembly $assembly -ErrorAction Stop
} catch {
    [PSCustomObject]@{
        Type    = "Error"
        Message = "Failed to import module: $($_.Exception.Message)"
    } | ConvertTo-Json -Compress | Write-Output
    exit 1
}

# --- List Exported Functions ---
$loadedModule = Get-Module -Name "dynamic_code_module_$assemblyName*"

if ($loadedModule -ne $null) {
    $exportedFunctions = $loadedModule.ExportedCommands.Keys
    [PSCustomObject]@{
        Type  = "Metadata"
        Funcs = $exportedFunctions
    } | ConvertTo-Json -Compress | Write-Output
} else {
    [PSCustomObject]@{
        Type    = "Error"
        Message = "Could not find the loaded module."
    } | ConvertTo-Json -Compress | Write-Output
    exit 1
}
