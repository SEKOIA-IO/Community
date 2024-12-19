import "pe"
import "hash"
        
rule implant_win_mysterysnail {
    meta:
        id = "dfd2eba8-eb9c-411a-b5e0-663593453e3d"
        version = "1.0"
        description = "Detect the MysterySnail using section hashes"
        author = "Sekoia.io"
        creation_date = "2021-10-13"
        classification = "TLP:CLEAR"
        
    condition:
        uint16(0)==0x5A4D and (
            pe.imphash() == "de0c9e6aec27d278ccdb6718b3e96e32"
            or for any i in (0..pe.number_of_sections-1) : (
                hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "a41b6fb1cc34d6393e30c13a58f6ecd4"
                or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "f263a2be76694feab7e2ce79ecf8b724"
                or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "e9056ae96619d7aa18daa973da592afc"
                or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "3e38e89e9e8329f5cff8a7022d88fff7"
                or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "ce78f8599167c63e8f1c8d3e789c4a60"
                or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "456d4f1096bf5c72cd6e1e3eb9980ec6"
                or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "37e2bff637001fc64566fe651757f66e"
            )
            or hash.md5(pe.rich_signature.clear_data) == "e4116fffa240ba6d91b400541ce85182"
        )
}
        