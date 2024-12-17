rule sekoiaio_infostealer_win_stormkitty {
    meta:
        id = "5014d2e5-af5c-4800-ab1e-b57de37a2450"
        version = "1.0"
        description = "Finds StormKitty samples (or their variants) based on specific strings"
        author = "Sekoia.io"
        creation_date = "2023-03-29"
        classification = "TLP:CLEAR"
        
    strings:
        $sk01 = "LimerBoy/StormKitty" ascii wide
        $sk02 = "StormKitty-Latest.log" wide
        $sk03 = "StormKitty.exe" ascii
        $sk04 = "Debug\\StormKitty.pdb" ascii
        $sk05 = "StormKitty.Implant" ascii
        
        $str01 = "set_sUsername" ascii
        $str02 = "set_sIsSecure" ascii
        $str03 = "set_sExpMonth" ascii
        $str04 = "WritePasswords" ascii
        $str05 = "WriteCookies" ascii
        $str06 = "sChromiumPswPaths" ascii
        $str07 = "sGeckoBrowserPaths" ascii
        $str08 = "Username: {1}" wide
        $str09 = "Password: {2}" wide
        $str10 = "encrypted_key\":\"(.*?)\"" wide
        
    condition:
    uint16(0) == 0x5A4D and
    ((1 of ($sk*) and 3 of ($str*)) or 7 of ($str*))
}
        