import "pe"
import "hash"
        
rule rat_win_ninerat {
    meta:
        id = "a9f4f78b-5b86-4ac1-9b9b-ba2672b938bf"
        version = "1.0"
        description = "Detect the NineRAT payload"
        author = "Sekoia.io"
        creation_date = "2023-12-12"
        classification = "TLP:CLEAR"
        hash1 = "47e017b40d418374c0889e4d22aa48633b1d41b16b61b1f2897a39112a435d30"
        hash2 = "82d4a0fef550af4f01a07041c16d851f262d859a3352475c62630e2c16a21def"
        
    strings:
        $ = "https://api.telegram.org/bot"
        $ = "/getMe"
        $ = "/upgrade"
        $ = "/getFile"
        $ = "/sendMessage"
        $ = ">> Request send time:"
        
    condition:
        // Strings
        all of them
        
        // Sections
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "3ce78c89e2c0e795ad3382aa12e99683"
        )
}
        