import "pe"
        
rule hacktool_win_gmer {
    meta:
        version = "1.0"
        description = "Dtect the GMER hacktool based string and UPX usage"
        author = "Sekoia.io"
        creation_date = "2022-09-09"
        id = "d2f1aba1-4222-45e5-95bd-4d7f08595cea"
        classification = "TLP:CLEAR"
        
    strings:
        $pac = "IDI_GMER" wide
        
        $str0 = "---- Processes - GMER %s ----" ascii
        $str1 = "E:\\projects\\cpp\\gmer\\Release\\gmer.pdb" ascii
        
    condition:
        uint16(0)==0x5A4D and
        (($pac and for any i in (0..pe.number_of_sections-1) : (
                pe.sections[i].name == "UPX0"
        )) or
        any of ($str*)) and filesize < 900KB
}
        