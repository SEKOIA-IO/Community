rule sekoiaio_implant_any_sliver {
    meta:
        id = "4b16f28a-2048-4044-8620-8e7a1651f2b1"
        source = "Sekoia.io"
        creation_date = "2021-11-08"
        description = "Rule which detects any Sliver implant PE/Dlls/ELFs/MAC-O."
        version = "1.1"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = ").GetActiveC2" ascii
        $s2 = ").GetVersion" ascii
        $s3 = ").GetReconnectInterval" ascii
        $s4 = ").GetProxyURL" ascii
        $s5 = ").GetPollInterval" ascii
        
    condition:
        ( uint16be(0) == 0x4d5a or
        uint32be(0) == 0x7f454c46 or
        uint32be(0) == 0xcffaedfe
        ) and (
            true and
            filesize < 11MB and
            filesize > 7MB
        ) and (
            all of ($s*)
        )
}
        