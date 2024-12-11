import "pe"
import "hash"
        
rule sekoiaio_implant_win_apt29_2022_10 {
    meta:
        id = "0f270e75-f687-4fdc-a980-fde81107a4d6"
        version = "1.0"
        description = "APT29 implants from October 2022"
        source = "Sekoia.io"
        creation_date = "2023-02-15"
        classification = "TLP:CLEAR"
        hash1 = "1cffaf3be725d1514c87c328ca578d5df1a86ea3b488e9586f9db89d992da5c4"
        hash2 = "381a3c6c7e119f58dfde6f03a9890353a20badfa1bfa7c38ede62c6b0692103c"
        
    condition:
        pe.imphash() == "39b818e7bac0a276f509f8c47e467666"
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "6621113d9f212c71b8dd3ce85c62b251"
        )
}
        