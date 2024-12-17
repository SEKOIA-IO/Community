rule sekoiaio_infostealer_win_stealc {
    meta:
        id = "aa78772e-9b31-40f3-84f4-b8302ea63a28"
        version = "1.0"
        description = "Find standalone Stealc sample based on decryption routine or characteristic strings"
        author = "Sekoia.io"
        creation_date = "2023-02-12"
        classification = "TLP:CLEAR"
        
    strings:
        $dec = { 55 8b ec 8b 4d ?? 83 ec 0c 56 57 e8 ?? ?? ?? ?? 6a 03 33 d2 8b f8 59 f7 f1 8b c7 85 d2 74 04 } //deobfuscation function
        
        $str01 = "------" ascii
        $str02 = "Network Info:" ascii
        $str03 = "- IP: IP?" ascii
        $str04 = "- Country: ISO?" ascii
        $str05 = "- Display Resolution:" ascii
        $str06 = "User Agents:" ascii
        $str07 = "%s\\%s\\%s" ascii
        
    condition:
        uint16(0) == 0x5A4D and ($dec or 5 of ($str*))
}
        