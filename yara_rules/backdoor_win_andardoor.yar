import "pe"
import "hash"
        
rule backdoor_win_andardoor {
    meta:
        id = "27f28f6e-b8fd-41dc-88a8-92f5a125a807"
        version = "1.0"
        description = "Detect the Andardoor backdoor used by Andariel"
        author = "Sekoia.io"
        creation_date = "2023-09-04"
        classification = "TLP:CLEAR"
        
    strings:
        $ = " : Deleted Dir" wide
        $ = " : Not Exists" wide
        $ = " : Deleted File" wide
        $ = " : Closed." wide
        $ = " : Opened." wide
        $ = "GoodLuck!" wide
        
    condition:
        // Strings
        uint16(0)==0x5A4D and all of them
        
        // PE section
        or for any i in (0..pe.number_of_sections-1) : (
            hash.md5(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) == "9fea4972270c492ca304f3663913ae63"
        )
        
        // PE resource
        or for any i in (0..pe.number_of_resources-1) : (
            hash.sha256(pe.resources[i].offset, pe.resources[i].length) == "34fde27c3c864efa6225e72016992d341f29cbbea638432a1c63ce05ca568300"
        )
}
        