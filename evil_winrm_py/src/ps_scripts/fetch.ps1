# This script is part of evil-winrm-py project https://github.com/adityatelange/evil-winrm-py
# It reads a file in chunks, converts each chunk to Base64, and outputs metadata and chunks as JSON.

# --- Define Parameters ---
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$FilePath
)

# --- Configuration ---
$bufferSize = 65536 # Read in 64 KB chunks

# --- Variables for disposal ---
$fileStream = $null # Initialize as null to handle disposal
$fileInfo = $null   # To store file information

# --- Pre-check and initial metadata ---
if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
    [PSCustomObject]@{
        Type        = "Error"
        Message     = "Error: The specified file path does not exist or is not a file: '$FilePath'"
    } | ConvertTo-Json -Compress | Write-Output # Pipe JSON to stdout
    exit 1 # Exit the script with an error code
}

try {
    $fileInfo = Get-Item -Path $FilePath
    $fileSize = $fileInfo.Length # Total file size in bytes
    $totalChunks = [System.Math]::Ceiling($fileSize / $bufferSize) # Calculate total chunks, rounding up
    $fileHash = (Get-FileHash -Path $FilePath -Algorithm MD5).Hash

    # Output initial file metadata as JSON
    [PSCustomObject]@{
        Type        = "Metadata"
        FilePath    = $FilePath
        FileSize    = $fileSize
        ChunkSize   = $bufferSize
        TotalChunks = $totalChunks
        FileHash    = $fileHash
        FileName    = $fileInfo.Name
    } | ConvertTo-Json -Compress | Write-Output # Pipe JSON to stdout

}
catch {
    [PSCustomObject]@{
        Type        = "Error"
        Message     = "Error getting file information or outputting metadata: $($_.Exception.Message)"
    } | ConvertTo-Json -Compress | Write-Output # Pipe JSON to stdout
    exit 1
}

# --- File Reading and Processing for Base64 Chunks ---
try {
    $fileStream = New-Object System.IO.FileStream($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
    $buffer = New-Object byte[] $bufferSize

    $chunkCounter = 0
    $totalBytesRead = 0

    while (($bytesRead = $fileStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $chunkCounter++ # Increment chunk counter

        # 1. Convert bytes to Base64
        $chunkBytes = New-Object byte[] $bytesRead
        [System.Array]::Copy($buffer, 0, $chunkBytes, 0, $bytesRead)
        $base64Chunk = [System.Convert]::ToBase64String($chunkBytes)

        # 2. Output the Base64 chunk as a JSON object
        [PSCustomObject]@{
            Type        = "Chunk"
            ChunkNumber = $chunkCounter
            Base64Data  = $base64Chunk
        } | ConvertTo-Json -Compress | Write-Output # Pipe JSON to stdout

        $totalBytesRead += $bytesRead
    }

}
catch {
    [PSCustomObject]@{
        Type        = "Error"
        Message     = "Error during Base64 chunk processing: $($_.Exception.Message)"
    } | ConvertTo-Json -Compress | Write-Output # Pipe JSON to stdout
}
finally {
    if ($fileStream) {
        $fileStream.Dispose()
    }
}
