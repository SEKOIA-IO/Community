import "pe"
import "hash"
        
rule merlin_win_exe {
    meta:
        id = "c9c57f5e-26c3-43be-b2cf-10f5129d3be4"
        author = "Sekoia.io"
        creation_date = "2022-01-03"
        description = "Detects Merling agent (PE)"
        version = "1.0"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "B.symtab" ascii
        $s2 = "github.com/Ne0nd0g/merlin" ascii
        $s3 = "github.com/lucas-clemente" ascii
        $s4 = "SendMerlinMessage" ascii
        
    condition:
        uint16(0)==0x5A4D
        and for any i in (0..pe.number_of_sections-1) : (
                        hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "07b5472d347d42780469fb2654b7fc54"
                )
        and all of them
        and $s1 at 591
        and filesize < 15MB
}
        