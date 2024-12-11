rule sekoiaio_apt_andariel_dorarat_strings {
    meta:
        id = "30388291-a287-489f-a060-c90a16cda217"
        version = "1.0"
        description = "Detects Dora RAT based on strings"
        source = "Sekoia.io"
        creation_date = "2024-06-17"
        classification = "TLP:CLEAR"
        
    strings:
        $x1 = "/encryption.go" ascii fullword
        $x2 = "/handshake.go" ascii fullword
        $x3 = "/trans_module.go" ascii fullword
        $enc_rsc = { 14 02 72 14 D3 4C 4A 49 55 36 14 DF 8D 6F 2D CF }
        
    condition:
        uint16be(0) == 0x4d5a and
        (all of ($x*) or $enc_rsc)
}
        