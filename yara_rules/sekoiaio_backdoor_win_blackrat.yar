import "pe"
import "hash"
        
rule sekoiaio_backdoor_win_blackrat {
    meta:
        id = "3a5a6290-6344-45ce-8929-ea5a4451840f"
        version = "1.0"
        description = "Detect Andariel's Black RAT malware"
        source = "Sekoia.io"
        creation_date = "2023-09-04"
        classification = "TLP:CLEAR"
        hash1 = "c2500a6e12f22b16e221ba01952b69c92278cd05632283d8b84c55c916efe27c"
        
    strings:
        $s1 = "I:/01___Tools/02__RAT/Black/Client_Go/Client.go"
        $s2 = "I:/01___Tools/02__RAT/Black/Client_Go/Define.go"
        $s3 = "I:/01___Tools/02__RAT/Black/Client_Go/Screenshot.go"
        
        // It is possible that it exists a Rust version of this RAT
        $x1 = "RAT/Black/Client"
        
    condition:
        uint16be(0) == 0x4d5a and (all of ($s*) or #x1 >= 3)
        
        // All section of the sample are unique. I use them for research purpose
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "74c4cdc9d33fc63aee7ae9659b6f8d24"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "298948afbe85985025e176605ee21176"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "e5ca54c5def3c7a950e6d4034dc86277"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "440ae899aea859458df5b6de7dbc5b34"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "98e46f76b965ffb58f6cd53ff8dc91c0"
        )
}
        