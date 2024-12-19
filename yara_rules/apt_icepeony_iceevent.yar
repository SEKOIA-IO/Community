rule apt_icepeony_iceevent {
    meta:
        id = "7d1f8b90-fde4-4d5c-a8a3-375db8aa88a1"
        version = "1.0"
        description = "Detects IceEvent Backdoor"
        author = "Sekoia.io"
        creation_date = "2024-10-21"
        classification = "TLP:CLEAR"
        hash = "07c291c9cea4430676c303128bbbb8e3"
        hash = "489b573b37ab8bc74cca3704e723b895"
        hash = "265f6cf778d26e62903fb295f89507e3"
        hash = "f5eb28dd29c91cc84818b74d7f138ff6"
        
    strings:
        $ = "Created a process" ascii fullword
        $ = "CreateProcess failed: %d"
        $ = "bind error:"
        $ = "Error creating pip: %d"
        $ = "listen error:"
        
    condition:
        uint16be(0) == 0x4d5a and
        4 of them and filesize < 500KB
}
        