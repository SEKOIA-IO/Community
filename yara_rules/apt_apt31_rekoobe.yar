import "elf"
        
rule apt_apt31_rekoobe {
    meta:
        id = "b1461a72-76ce-4cc5-ac84-3cc87454d288"
        version = "1.0"
        description = "Find Rekoobe sample via Trend Elf Hash (telfhash)"
        author = "Sekoia.io"
        creation_date = "2023-07-10"
        classification = "TLP:CLEAR"
        
    condition:
        uint32be(0) == 0x7f454c46 and
        filesize < 100KB and elf.telfhash() == "t18fc080c7c6b56a34a7f32538ac7c407982035e1581561b207f50c955d93b408404c5ef"
}
        