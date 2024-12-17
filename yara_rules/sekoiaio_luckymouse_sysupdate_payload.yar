rule sekoiaio_luckymouse_sysupdate_payload {
    meta:
        id = "97df4700-de35-49a0-869e-ed89a6d9cbdd"
        version = "1.0"
        description = "Detects decryption routine prologue of sysupdate samples"
        author = "Sekoia.io"
        creation_date = "2022-08-19"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = { DB ?? ?? C9 66 B9 ?? ?? E8 FF FF FF FF }
        
    condition:
        filesize < 1MB and
        all of them
}
        