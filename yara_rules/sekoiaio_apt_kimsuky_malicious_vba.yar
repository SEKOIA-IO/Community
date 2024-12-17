rule sekoiaio_apt_kimsuky_malicious_vba {
    meta:
        id = "2dbe2431-3592-4395-8164-49abae4a5a3d"
        version = "1.0"
        description = "Detects malicious VBA used by Kimsuky"
        author = "Sekoia.io"
        creation_date = "2022-08-30"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Certutil -decode %TMP%"
        $ = "%LOCALAPPDATA%\\Microsoft\\Office"
        
    condition:
        uint32be(0) == 0xD0CF11E0 and 
        filesize < 1MB and
        all of them
}
        