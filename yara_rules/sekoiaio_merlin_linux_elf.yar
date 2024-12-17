import "elf"
import "hash"
        
rule sekoiaio_merlin_linux_elf {
    meta:
        id = "d9c57f5e-26c3-43be-b2cf-10f5129d3be6"
        author = "Sekoia.io"
        creation_date = "2022-01-03"
        description = "Detects Merling agent (ELF)"
        version = "1.0"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "github.com/Ne0nd0g/merlin" ascii
        $s2 = "github.com/refraction-networking" ascii
        $s3 = "SendMerlinMessage" ascii
        
    condition:
        uint32(0)==0x464c457f
                and for any i in (0..elf.number_of_sections-1) : (
                        hash.md5(elf.sections[i].offset, elf.sections[i].size) == "80199718ff1821a3fe914cd2279ab3a0"
        )
                and for any i in (0..elf.number_of_sections-1) : (
                        hash.md5(elf.sections[i].offset, elf.sections[i].size) == "7dea362b3fac8e00956a4952a3d4f474"
        )
                and for any i in (0..elf.number_of_sections-1) : (
                        hash.md5(elf.sections[i].offset, elf.sections[i].size) == "d41d8cd98f00b204e9800998ecf8427e"
        )
                and for any i in (0..elf.number_of_sections-1) : (
                        hash.md5(elf.sections[i].offset, elf.sections[i].size) == "91476dafa5ef669483350538fa6ec4cb"
                )
        and all of them
        and filesize < 15MB
}
        