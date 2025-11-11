# This script is part of evil-winrm-py project https://github.com/adityatelange/evil-winrm-py
# It reads a Base64 encoded chunk of bytes, writes it to a file, and optionally appends to an existing file.
# It also calculates the MD5 hash of the file after writing if required.

# --- Define Parameters ---
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Base64Chunk,   # The Base64 encoded chunk of bytes
    [Parameter(Mandatory=$true, Position=1)]
    [int]$ChunkType = 0,    # 0 for new file, 1 for appending to existing file
    [Parameter(Mandatory=$false, Position=2)]
    [string]$TempFilePath,  # The temporary file path to write/append the bytes to
    [Parameter(Mandatory=$false, Position=3)]
    [string]$FilePath,      # The file path to write/append the bytes to
    [Parameter(Mandatory=$false, Position=4)]
    [string]$FileHash       # The MD5 hash of the file
)

# --- Variables for disposal ---
$fileStream = $null # Initialize as null for safety in finally block


# --- Pre-checks ---
# IF chunkPosition is 0 or 3 its a new file
if ($ChunkType -eq 0 -or $ChunkType -eq 3) {
    # If this is the first chunk, create a unique temporary file path
    $TempFilePath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())
    # Output initial file metadata as JSON
    [PSCustomObject]@{
        Type            = "Metadata"
        TempFilePath    = $TempFilePath
    } | ConvertTo-Json -Compress | Write-Output # Pipe JSON to stdout
}

# --- Main Logic ---

try {
    # Decode the Base64 chunk into bytes
    $chunkBytes = [System.Convert]::FromBase64String($Base64Chunk)

    # Open the file in Append mode.
    # If the file doesn't exist, it will be created.
    # If it exists, new bytes will be added to the end.
    $fileStream = New-Object System.IO.FileStream(
        $TempFilePath,
        [System.IO.FileMode]::Append, # Use Append mode
        [System.IO.FileAccess]::Write
    )

    # Write the decoded bytes to the file
    # $ChunkSize here is critical and should be the actual length of $chunkBytes for this specific chunk
    $fileStream.Write($chunkBytes, 0, $chunkBytes.Length) # Use $chunkBytes.Length for safety
    $fileStream.Close()
}
catch {
    $FullExceptionMessage = "$($_.Exception.GetType().FullName): $($_.Exception.Message)"
    [PSCustomObject]@{
        Type        = "Error"
        Message     = "Error processing chunk or writing to file: $FullExceptionMessage"
    } | ConvertTo-Json -Compress | Write-Output # Pipe JSON to stdout
}
finally {
    # Ensure the file stream is closed to release the file lock and flush buffers
    if ($fileStream) {
        $fileStream.Dispose()
    }
}

# --- Calculate checksum ---
# Caculate the MD5 hash of the file after writing if ChunkType is 1 or 3
if ($ChunkType -eq 1 -or $ChunkType -eq 3) {
    try {
        if ($TempFilePath) {
            # If a file hash is provided, verify it
            $calculatedHash = (Get-FileHash -Path $TempFilePath -Algorithm MD5).Hash
            if ($calculatedHash -eq $FileHash) {
                # If the hash matches, move the temporary file to the final destination
                [System.IO.File]::Delete($FilePath)
                [System.IO.File]::Move($TempFilePath, $FilePath)

                $fileInfo = Get-Item -Path $FilePath
                $fileSize = $fileInfo.Length # Total file size in bytes
                $fileHash = (Get-FileHash -Path $FilePath -Algorithm MD5).Hash

                # Output initial file metadata as JSON
                [PSCustomObject]@{
                    Type        = "Metadata"
                    FilePath    = $FilePath
                    FileSize    = $fileSize
                    FileHash    = $fileHash
                    FileName    = $fileInfo.Name
                } | ConvertTo-Json -Compress | Write-Output # Pipe JSON to stdout
            } else {
                [PSCustomObject]@{
                    Type        = "Error"
                    Message     = "File hash mismatch. Expected: $FileHash, Calculated: $calculatedHash"
                } | ConvertTo-Json -Compress | Write-Output # Pipe JSON to stdout
            }
        } else {
            [PSCustomObject]@{
                Type        = "Error"
                Message     =  "File hash not provided for verification."
            } | ConvertTo-Json -Compress | Write-Output # Pipe JSON to stdout
        }
    }
    catch {
        $FullExceptionMessage = "$($_.Exception.GetType().FullName): $($_.Exception.Message)"
        [PSCustomObject]@{
            Type        = "Error"
            Message     = "Error processing chunk or writing to file: $FullExceptionMessage"
        } | ConvertTo-Json -Compress | Write-Output # Pipe JSON to stdout
    }
}
