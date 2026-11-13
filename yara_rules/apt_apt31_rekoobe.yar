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
        filesize < 100KB and elf.telfhash() == "T18FC080C7C6B56A34A7F32538AC7C407982035E1581561B207F50C955D93B408404C5EF"
}
        
