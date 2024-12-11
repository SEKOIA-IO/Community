rule sekoiaio_tool_powershell_unicorn {
    meta:
        id = "287c1669-2ee1-488e-bf66-a99bfe309c90"
        version = "1.0"
        description = "Detects Unicorn Powershell"
        source = "Sekoia.io"
        creation_date = "2022-08-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = ").value.toString() ('JAB" ascii wide
        $ = ").value.toString());powershell (" ascii wide
        $ = "powershell /w 1 " ascii wide
        
    condition:
        all of them and filesize < 100KB
}
        