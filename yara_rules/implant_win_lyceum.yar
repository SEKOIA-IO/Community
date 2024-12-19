import "pe"
import "hash"
        
rule implant_win_lyceum {
    meta:
        id = "e061562f-9c17-4ef4-b7f9-2c6708bb6570"
        version = "1.0"
        description = "Detect the DnsSystem malware used by Lyceum in March 2022"
        author = "Sekoia.io"
        creation_date = "2022-06-13"
        classification = "TLP:CLEAR"
        reference = "https://www.zscaler.com/blogs/security-research/lyceum-net-dns-backdoor"
        
    strings:
        $ = "$02c7afab-7f96-4dfa-b452-832e3624e270" ascii
        $ = "C:\\Users\\u1\\Downloads\\Compressed\\article_src\\DnsDig\\DnsDig\\obj\\Release\\DnsDig.pdb" ascii
        
    condition:
        uint16(0)==0x5A4D and 1 of them
        
        // Section
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "d0e0c140e4831f835bcdcc6b463f3acc"
        )
        
        // Resource
        or for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "22c92a1ba6ffd828637d7045261db7a45608ddd6d7c85836af011b3c679c725f"
        )
}
        