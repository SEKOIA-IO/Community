import "pe"
import "hash"
        
rule ransomware_win_blackmatter {
    meta:
        id = "9b2d8ac3-b4d1-40f5-ac57-411547dcb2cf"
        version = "1.0"
        description = "Detect Black matter ransomware (2021-07-23)"
        author = "Sekoia.io"
        creation_date = "2021-08-03"
        classification = "TLP:CLEAR"
        
    condition:
        for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "5e89d335de2021a2c268acf00ec513e5"
        )
}
        