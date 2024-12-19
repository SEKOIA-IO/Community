import "pe"
        
rule crybercrime_prophetspider_proxy {
    meta:
        id = "b7637fc3-bf81-40c4-869c-1c283574e0a7"
        version = "1.0"
        description = "Detects the Winntaa decryption loop or imphash"
        author = "Sekoia.io"
        creation_date = "2022-02-17"
        classification = "TLP:CLEAR"
        
    strings:
        $ = { 56
        57
        48 8D 95 F0 FE FF FF
        31 C0
        66 21 02
        48 89 CE
        AC
        48 89 D7
        4C 89 C2
        88 D4
        30 C2
        0F B6 CA
        48 89 95 E8 FE FF FF
        AC
        30 E0
        AA
        E2 FA
        88 C8
        AA
        48 8D 85 F0 FE FF FF
        48 8B 95 E8 FE FF FF
        5F
        5E
        C3 }
        
    condition:
        uint16be(0) == 0x4d5a and
        (all of them or pe.imphash() == "55e0b8e5b4d787c680ada4e450789a4d")
}
        