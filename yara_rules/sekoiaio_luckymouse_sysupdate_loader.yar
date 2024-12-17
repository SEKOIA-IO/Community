rule sekoiaio_luckymouse_sysupdate_loader {
    meta:
        id = "6007e846-d467-4d07-b345-e25191b7c8bc"
        version = "1.0"
        description = "Detects decryption routine prologue of sysupdate loader"
        author = "Sekoia.io"
        creation_date = "2022-08-19"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = { DB D4 33 C9 66 B9 ?? ?? E8 FF FF FF FF }
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        all of them
}
        