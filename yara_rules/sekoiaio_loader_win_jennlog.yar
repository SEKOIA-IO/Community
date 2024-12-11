import "pe"
import "hash"
        
rule sekoiaio_loader_win_jennlog {
    meta:
        id = "a69088e5-207f-494f-876b-766b8050e8c2"
        version = "1.0"
        description = "Jennlog loader used to deliver the Apostle ransomware"
        source = "Sekoia.io"
        creation_date = "2021-10-04"
        classification = "TLP:CLEAR"
        reference = "https://www.sentinelone.com/labs/new-version-of-apostle-ransomware-reemerges-in-targeted-attack-on-higher-education/"
        
    condition:
        pe.timestamp == 3140259112
        or
        for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "4c4577276ff0323d9aedcc39ecf2c964"
        )
        or
        for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "8476a7fca587f1e5d3ae076293b9fbcccbebc4bd4f7b783228ad5da39305a3d9"
        )
}
        