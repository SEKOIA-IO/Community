import "pe"
import "hash"
        
rule sekoiaio_backdoor_win_sidewinder_cobaltstrike_2022_09 {
    meta:
        id = "b5e8f87a-4a2c-49bb-aa98-bf3fb5056b23"
        version = "1.0"
        description = "Detect the SideWinder malware"
        source = "Sekoia.io"
        creation_date = "2022-10-24"
        classification = "TLP:CLEAR"
        
    strings:
        // eNEVER GONNA GIVE YOU UP!
        $s1 = {65004e004500560045005200200047004f004e004e00410020004700490056004500200059004f0055002000550050002100}
        
    condition:
        $s1

        //Imphash
        or pe.imphash() == "b1e345b2d78e4b82617d995d18100790"

        //Sections
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "ac989507d4af352fa354560efef99ba6"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "8090b29a44c750b7b21287f9639fe747"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "ea8693d6bacf3e7876f717a3d8abc433"
        )
}
        