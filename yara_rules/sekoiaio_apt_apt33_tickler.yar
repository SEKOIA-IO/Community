import "hash"
import "pe"
        
rule sekoiaio_apt_apt33_tickler {
    meta:
        id = "e9ecf678-350c-47d2-ab4c-522974c70a45"
        version = "1.0"
        description = "Detects APT33 Tickler malware"
        source = "Sekoia.io"
        creation_date = "2024-08-29"
        classification = "TLP:CLEAR"
        hash = "8bd712b0a49f4fecd39d30ebd121832c"
        hash = "3f29429fce0168748d7cc75e1478aedc"
        
    condition:
        uint16be(0) == 0x4d5a and
        (hash.md5(pe.rich_signature.clear_data) == "2fe65623e6b22577516a4cd051ec3baa"
        or pe.imphash() == "a5accd1a0d3eaf2c131bc662dd7ff8ea")
}
        