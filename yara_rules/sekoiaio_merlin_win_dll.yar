import "pe"
import "hash"
        
rule sekoiaio_merlin_win_dll {
    meta:
        id = "c9c57f5e-26c3-43be-b2cf-10f5129d3be5"
        author = "Sekoia.io"
        creation_date = "2022-01-03"
        description = "Detects Merling agent (DLL)"
        version = "1.0"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = ".CRT" ascii
        $s2 = ".tls" ascii
        $s3 = "github.com/Ne0nd0g/merlin" ascii
        $s4 = "github.com/lucas-clemente" ascii
        $s5 = "SendMerlinMessage" ascii
        
    condition:
        uint16(0)==0x5A4D
                and pe.imphash() == "da7f8acb6151c95be088a02465d68ef8"
                and for any i in (0..pe.number_of_sections-1) : (
                        hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "491d9a18aea3d0eb3653fdaf0b9b86bb"
        )
                and for any i in (0..pe.number_of_sections-1) : (
                        hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "d41d8cd98f00b204e9800998ecf8427e"
        )
                and for any i in (0..pe.number_of_sections-1) : (
                        hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "bf619eac0cdf3f68d496ea9344137e8b"
        )
                and for any i in (0..pe.number_of_sections-1) : (
                        hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "ce7969c1e894363133e386361be064e5"
        )
                and for any i in (0..pe.number_of_sections-1) : (
                        hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "c6179cdcd9ba0758a18a1280f98062eb"
                )
        and all of them
        and $s1 at 712 
        and $s2 at 752 
        and filesize < 15MB
}
        