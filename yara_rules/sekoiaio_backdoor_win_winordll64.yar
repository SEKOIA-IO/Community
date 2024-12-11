import "hash"
import "pe"
        
rule sekoiaio_backdoor_win_winordll64 {
    meta:
        id = "86a32538-bc69-47ea-9842-4af360588c27"
        version = "1.0"
        description = "Detect the WinorDLL64 backdoor"
        source = "Sekoia.io"
        creation_date = "2023-02-24"
        classification = "TLP:CLEAR"
        
    condition:
        hash.md5(pe.rich_signature.clear_data) == "d16713cbfe04151b3a9e832c8afd55df"
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "3f638774c2565594029fb52ceb67db7a"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "f9416bfb43b2c70837927e43e7591a2a"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "6eede2cebaef39eec5bd1c24c809e3dc"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "1177658fb0469cd5982102c9f3cd2eea"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "658d877d1bf0d2928b2c3efec9ec06cf"
        )
        or pe.imphash() == "d6b6f8cdffb06f469e06c7af9639897c"
}
        