import "pe"
import "hash"
        
rule sekoiaio_wiper_win_dnwipe {
    meta:
        id = "522fdaa5-8fe6-4e37-aaf8-13e3a7787d21"
        version = "1.0"
        description = "Detect the dnWipe malware"
        source = "Sekoia.io"
        creation_date = "2022-11-21"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "dnWIPE"
        $ = "dnWIPE" wide
        $ = "C:\\Users\\Admin1\\source\\repos\\dnWIPE\\dnWIPE\\obj\\Debug\\dnWIPE.pdb"
        
    condition:
        // Strings
        uint16(0)==0x5A4D and all of them and filesize < 50KB

        // Resource
        or for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "93290ef6447b0a16b92e50a1652ac3eb8f1237cc5f8005e080750fb58c19d230"
        )
}
        