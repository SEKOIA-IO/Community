rule ransomware_win_fonix {
    meta:
        id = "b28467d5-69a0-4a8b-8938-8fdac2ae8d19"
        version = "1.0"
        description = "Detect the Fonix / XINOF ransomware by spotting its specific debug path"
        author = "Sekoia.io"
        creation_date = "2021-10-07"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "Ransomware\\Fonix" ascii
        $s2 = "Release\\Fonix.pdb" ascii
        
    condition:
        uint16(0)==0x5A4D and all of them
}
        