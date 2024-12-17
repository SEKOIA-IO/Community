rule sekoiaio_apt_muddywater_powershell_reverse_secure_proxy {
    meta:
        id = "b255f327-cb56-41b7-82f7-83ee23f791a5"
        version = "1.0"
        description = "Detects PowerShell Reverse Secure Proxy"
        author = "Sekoia.io"
        creation_date = "2023-11-14"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "$CS.Read($buff,4,2) | Out-Null" ascii wide
        $ = "$DP = $buff[2]*256 + $buff[3]" ascii wide
        $ = "$PS3.BeginInvoke() | Out-Null" ascii wide
        
    condition:
        all of them
}
        