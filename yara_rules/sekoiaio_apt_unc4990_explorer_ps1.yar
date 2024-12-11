rule sekoiaio_apt_unc4990_explorer_ps1 {
    meta:
        id = "2e1abbbf-f9b7-4147-b7da-3544cbc4a5f1"
        version = "1.0"
        description = "Detects powershell script (explorer.ps1)"
        source = "Sekoia.io"
        creation_date = "2024-02-01"
        classification = "TLP:CLEAR"
        
    strings:
        $s0 = "$(get-location).Path"
        $s1 = "+ \"\\Runtime Broker.exe"
        $s2 = "Start-Process -FilePath"
        $s3 = "-Wait;"
        $s4 = "Start-Sleep -s"
        
    condition:
        all of them and @s3-@s2 < 35
}
        