rule sekoiaio_tool_nssm_strings {
    meta:
        id = "fab99d44-6494-4bfc-80c0-67c45bad0425"
        version = "1.0"
        description = "Detects nssm tool"
        source = "Sekoia.io"
        creation_date = "2024-09-06"
        classification = "TLP:CLEAR"
        hash = "beceae2fdc4f7729a93e94ac2ccd78cc"
        
    strings:
        $ = "nssm start <servicename>" wide
        $ = "nssm stop <servicename>" wide
        $ = "nssm restart <servicename>" wide
        $ = "nssm status <servicename>" wide
        $ = "nssm rotate <servicename>" wide
        
    condition:
        uint16be(0) == 0x4d5a 
        and all of them 
        and filesize < 500KB
}
        