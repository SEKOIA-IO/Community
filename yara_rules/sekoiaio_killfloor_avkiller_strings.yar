rule sekoiaio_killfloor_avkiller_strings {
    meta:
        id = "ae6908c3-27d4-4d2c-af21-a9548dfcd487"
        version = "1.0"
        description = "Kill-Floor strings"
        author = "Sekoia.io"
        creation_date = "2024-10-29"
        classification = "TLP:CLEAR"
        hash = "9f16176ac20f7855fa960d321e156d69"
        hash = "4b019e9ed2de734e242602abce06f7c1"
        hash = "81ae32d9de8fd21acfc61d62f3292277"
        hash = "7cb2c4560e02c25463ec70e222ad0018"
        
    strings:
        $ = "sc create aswArPot.sys type=kernel binpath=%s" ascii
        $ = "sc start aswArPot.sys" ascii
        $ = "[*] Enumerating target processes" ascii
        $ = "[*] Entering main loop... " ascii
        $ = "aswArPot.pdb" ascii
        $ = "SeConvertStringSecurityDescriptorToSecurityDescriptor" wide
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 1MB and filesize > 20KB and 
        6 of them
}
        