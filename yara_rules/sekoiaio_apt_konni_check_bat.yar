rule sekoiaio_apt_konni_check_bat {
    meta:
        id = "f05e6ba2-c128-4c17-8f74-f7640103c859"
        version = "1.0"
        description = "Script used to performs check before executing Konni"
        source = "Sekoia.io"
        creation_date = "2023-11-27"
        classification = "TLP:CLEAR"
        
    strings:
        $ = ":64BIT"
        $ = ":32BIT"
        $ = ":INSTALL"
        $ = ":EXIT"
        $ = "netpp.dll"
        $ = "wpns.dll"
        $ = "netpp64.dll"
        $ = "wpns64.dll"
        $ = "rundll32"
        
    condition:
        filesize < 1MB and 7 of them
}
        