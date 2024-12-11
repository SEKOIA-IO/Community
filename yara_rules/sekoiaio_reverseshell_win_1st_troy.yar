import "pe"
import "hash"
        
rule sekoiaio_reverseshell_win_1st_troy {
    meta:
        id = "b40b742d-8b1e-4d99-8df5-6cb8c9a7d8bd"
        version = "1.0"
        description = "Detect the 1st Troy Reverse Shell agent used by Andariel"
        source = "Sekoia.io"
        creation_date = "2023-09-04"
        classification = "TLP:CLEAR"
        hash1 = "186a6663eb91999b3e2637898ab40034f5fcd451150c9199d9b49328e64f90b5"
        hash2 = "5b015e69629de37507e96ce258c27479d157714121d7c622698c6d1d6b547425"
        
    strings:
        $s1 = "1th Troy/02___Go/Reverse_Base64_Pipe"
        
    condition:
        uint16be(0) == 0x4d5a and all of them 
        
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "657d7495796c36297ec1c13aaedf1dd3"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "debd992f27402355766cf3b5b47abe94"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "687d2535086bd055af5716760a2d87ce"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "78389349844e8d2d719603fc389779bf"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "44563b597e806af8a9ebe026c9ea6a53"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "5db8685a067d106fe66292b828a2161c"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "1268012f292e60785825726967a4e63e"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "c7b760c8b603f39a5ff9867accbad427"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "d28526f9543ecf429de4a863b8901575"
        )
}
        