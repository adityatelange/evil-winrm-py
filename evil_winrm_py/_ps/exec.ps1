# This script is part of evil-winrm-py project https://github.com/adityatelange/evil-winrm-py
# It runs a dotnet executable in memory from a Base64 string and captures its output.

# --- Define Parameters ---
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Base64Exe, # Base64 encoded executable content

    [Parameter(Mandatory=$false, Position=1)]
    [string[]]$Args     # Arguments to pass to the executable
)

# --- Decode Base64 and Load Assembly ---
$exeBytes = [System.Convert]::FromBase64String($Base64Exe)
$assembly = [System.Reflection.Assembly]::Load($exeBytes)

# --- Execute the Entry Point and Capture Output ---
$entryPoint = $assembly.EntryPoint

if ($entryPoint -eq $null) {
    Write-Error "Error: The provided executable does not have an entry point."
    exit 1
}

# Redirect STDOUT and STDERR
$stdout = New-Object System.IO.StringWriter
$stderr = New-Object System.IO.StringWriter
$oldOut = [Console]::Out
$oldErr = [Console]::Error
[Console]::SetOut($stdout)
[Console]::SetError($stderr)

# Invoke the entry point method and pass arguments if any
$result = $entryPoint.Invoke($null, @(,($Args)))

# Capture outputs
$stdOutContent = $stdout.ToString()
$stdErrContent = $stderr.ToString()

# Log outputs as Plain text
if ($stdOutContent -ne "") {
    Write-Output $stdOutContent.Trim()
}
if ($stdErrContent -ne "") {
    Write-Error $stdErrContent.Trim()
}
if ($result) {
    Write-Output $result.Trim()
}

# Restore original STDOUT and STDERR
[Console]::SetOut($oldOut)
[Console]::SetError($oldErr)
