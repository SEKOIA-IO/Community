rule sekoiaio_loader_win_squirrelwaffle {
    meta:
        id = "bea3125e-6e84-435f-855b-fd3239a0deac"
        version = "1.0"
        description = "Detect the Squirrelwaffle DLL"
        author = "Sekoia.io"
        creation_date = "2021-09-20"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "AEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE" ascii
        $s2 = "c:\\equal\\True\\bird_Select\\780\\true.pdb" ascii
        
    condition:
        uint16(0)==0x5A4D and all of them
}
        