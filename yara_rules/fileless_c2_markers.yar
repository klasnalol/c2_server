rule C2_Flag_Marker
{
    meta:
        description = "Detects ATT&CK-style FLAG markers in memory"
        author = "forensic_analysis"
        technique = "T1059.001,T1083,T1105,T1041,T1027"
    strings:
        $flag = /FLAG\{T\d{4}(\.\d{3})?-[a-z0-9_-]+\}/ nocase
    condition:
        any of them
}

rule C2_URL_Pattern
{
    meta:
        description = "Detects C2 URL patterns used in lab experiments"
        author = "forensic_analysis"
    strings:
        $c1 = "192.168.122.1:8080" nocase
        $c2 = "192.168.122.1:8080/get/" nocase
        $c3 = "192.168.122.1:8080/collect" nocase
        $c4 = "/get/stage1_windows.ps1" nocase
        $c5 = "/get/obfuscated_windows.ps1" nocase
        $c6 = "/get/stage2_download_cradle.ps1" nocase
    condition:
        any of them
}

rule PowerShell_Download_Cradle
{
    meta:
        description = "Detects PowerShell download-and-execute patterns"
        author = "forensic_analysis"
        technique = "T1059.001,T1105"
    strings:
        $a = "Invoke-WebRequest" nocase
        $b = "IEX" nocase
        $c = "DownloadString" nocase
        $d = "New-Object Net.WebClient" nocase
        $e = "-ExecutionPolicy Bypass" nocase
        $f = "-NoProfile" nocase
    condition:
        2 of them
}

rule Base64_Obfuscation_Runtime
{
    meta:
        description = "Detects Base64 decode routines at runtime"
        author = "forensic_analysis"
        technique = "T1027"
    strings:
        $a = "System.Convert::FromBase64String" nocase
        $b = "System.Text.Encoding::UTF8.GetString" nocase
        $c = "[System.Convert]::FromBase64String" nocase
    condition:
        any of them
}

rule WMI_Persistence_Artifact
{
    meta:
        description = "Detects WMI event subscription artifacts"
        author = "forensic_analysis"
        technique = "T1546.003"
    strings:
        $a = "__EventFilter" nocase
        $b = "CommandLineEventConsumer" nocase
        $c = "__FilterToConsumerBinding" nocase
        $d = "WmiPrvSE.exe" nocase
    condition:
        any of them
}

rule Registry_Run_Persistence
{
    meta:
        description = "Detects registry Run key persistence strings"
        author = "forensic_analysis"
        technique = "T1547.001"
    strings:
        $a = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $b = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $c = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
    condition:
        any of them
}

rule MITRE_Technique_Reference
{
    meta:
        description = "Detects MITRE ATT&CK technique ID references"
        author = "forensic_analysis"
    strings:
        $t = /\bT\d{4}(\.\d{3})?\b/ nocase
    condition:
        any of them
}
