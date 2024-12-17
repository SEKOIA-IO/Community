rule sekoiaio_backdoor_lin_bifrost {
    meta:
        id = "9726b5f5-8cc3-4fad-950b-f20cac04d496"
        version = "1.0"
        description = "Detect the Bifrost backdor based on strings"
        author = "Sekoia.io"
        creation_date = "2024-03-05"
        classification = "TLP:CLEAR"
        reference = "https://unit42.paloaltonetworks.com/new-linux-variant-bifrost-malware/"
        hash1 = "8e85cb6f2215999dc6823ea3982ff4376c2cbea53286e95ed00250a4a2fe4729"
        hash2 = "2aeb70f72e87a1957e3bc478e1982fe608429cad4580737abe58f6d78a626c05"
        hash3 = "f2bef6bed27f4b527118dd62b4035003c14afaffa72729c8117f213623f644ec"
        
    strings:
        $ = "%c2%s%c3%u%c4%u-%.2u-%.2u %.2u:%.2u"
        $ = "%c1%s%c3D%c4%u-%.2u-%.2u %.2u:%.2u"
        
    condition:
        uint32be(0) == 0x7f454c46 and all of them
}
        