import "pe"
import "hash"
        
rule sekoiaio_wiper_win_isaacwiper {
    meta:
        id = "b081e3a3-612e-46ae-93af-82e7ee98fcf7"
        version = "1.0"
        description = "Detect the IsaacWiper using multiple methods + ReversingLab rule's condition"
        author = "Sekoia.io"
        creation_date = "2022-03-15"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "getting drives..." wide
        $s2 = "physical drives:" wide
        $s3 = "-- system physical drive" wide
        $s4 = "-- physical drive" wide
        $s5 = "logical drives:" wide
        $s6 = "-- system logical drive:" wide
        $s7 = "-- logical drive:" wide
        $s8 = "start erasing physical drives..." wide
        $s9 = "-- FAILED" wide
        $s10 = "-- start erasing logical drive" wide
        $s11 = "start erasing system physical drive..." wide
        $s12 = "system physical drive -- FAILED" wide
        $s13 = "start erasing system logical drive" wide
        
    condition:
        // Imphash
        pe.imphash() == "a4b162717c197e11b76a4d9bc58ea25d"
        
        // Section hashs
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "06d63fddf89fae3948764028712c36d6"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "48f101db632bb445c21a10fd5501e343"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "5efc98798d0979e69e2a667fc20e3f24"
            or hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "9676f7c827fb9388358aaba3e4bd0cc6"
        )
        
        // Rich header
        or hash.md5(pe.rich_signature.clear_data) == "ec862d3013903478c2ff8dce2792815f"
        
        // Strings
        or all of ($s*)
}
        