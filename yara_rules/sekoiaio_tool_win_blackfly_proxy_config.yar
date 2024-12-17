import "pe"
import "hash"
        
rule sekoiaio_tool_win_blackfly_proxy_config {
    meta:
        id = "c8a8be5d-bd28-4306-9466-ad582e53fede"
        version = "1.0"
        description = "Detect Blackfly proxy configuration tool"
        author = "Sekoia.io"
        creation_date = "2023-02-28"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "c:\\ProgramData\\l.dat"
        $ = "C:\\ProgramData\\b.dat"
        $ = "winmm_DotNetfile.dll"
        
    condition:
        pe.imphash() == "ff47f65286cc51a1328bc94efbf4007f"
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "f5923d4331f7e84fbbbd6fd84b6d3e6a"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "56acc10233c711a4eba9ca9aeab47e30"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "824dcebe93ac83bf5c95c781a60b3578"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "ec716a08b5e647f5c00c5dfc079dfa62"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "5cb63f7392c9e05c22e89cd86bd7f718"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "ee04e245066e25edd3062d823f15deda"
        )
        or (uint16(0)==0x5A4D and 1 of them)
}
        