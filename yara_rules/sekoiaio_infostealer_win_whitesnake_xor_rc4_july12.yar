rule sekoiaio_infostealer_win_whitesnake_xor_rc4_july12 {
    meta:
        id = "f2ebfcbd-9667-459a-a543-ce0be62c0dc4"
        version = "1.0"
        description = "Detects WhiteSnake Stealer XOR and RC4 version"
        source = "Sekoia.io"
        creation_date = "2023-07-12"
        classification = "TLP:CLEAR"
        
    strings:
        $1 = {FE 0C 00 00 FE 09 00 00 FE 0C 02 00 6F ?? 00 00 0A FE 0C 03 00 61 D1 FE 0E 04 00 FE}
        $2 = {61 6e 61 6c 2e 6a 70 67}
        $3 = {73 68 69 74 2e 6a 70 67}
        $4 = {FE 0C ?? 00 20 00 01 00 00 3F ?? FF FF FF 20 00 00 00 00 FE 0E ?? 00 38 ?? 00 00 00 FE 0C}
        $5 = "qemu" wide
        $6 = "vbox" wide
        
    condition:
        ($1 and $2 and filesize < 600KB) or ($3 and $4 and $5 and $6 and filesize < 300KB)
}
        