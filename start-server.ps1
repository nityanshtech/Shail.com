$ErrorActionPreference = "Stop"

$securePassword = Read-Host "Set a NEW admin password (at least 14 characters)" -AsSecureString
if ($securePassword.Length -lt 14) {
    $securePassword.Dispose()
    throw "The admin password must be at least 14 characters."
}

$passwordPointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
try {
    $env:ADMIN_PASSWORD = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
    node (Join-Path $PSScriptRoot "server.js")
}
finally {
    Remove-Item Env:ADMIN_PASSWORD -ErrorAction SilentlyContinue
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    $securePassword.Dispose()
}
