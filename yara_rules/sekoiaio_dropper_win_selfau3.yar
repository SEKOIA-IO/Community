rule sekoiaio_dropper_win_selfau3 {
    meta:
        id = "2d005a54-b013-40e9-b88a-30454e4b22af"
        version = "1.0"
        description = "Finds SelfAU3 Dropper samples based on specific strings"
        source = "Sekoia.io"
        creation_date = "2024-02-12"
        classification = "TLP:CLEAR"
        
    strings:
        $sfx = "!Require Windows" ascii
        
        $ins01 = ";!@Install@!UTF-8!" ascii
        $set =  {53 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 3d 22 [1-15] 3d ?? 22} //SetEnvironment="??..?=?"
        $run = "RunProgram=\"hidcon:c" ascii
        $ins02 = ";!@InstallEnd@!" ascii
        
    condition:
        $sfx at 77 and
        $set in (@ins01..@ins01+500) and
        #set > 5 and
        $run in (@set..@set+1000) and
        $ins02 in (@run..@run+500)
}
        