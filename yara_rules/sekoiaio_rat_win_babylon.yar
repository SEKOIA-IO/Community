rule sekoiaio_rat_win_babylon {
    meta:
        id = "ba9ab80a-ad7e-4746-aff2-9328440cbb25"
        version = "1.0"
        description = "Finds Babylon RAT samples based on specific strings"
        author = "Sekoia.io"
        creation_date = "2023-08-22"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "ParadoxRAT_Client" ascii
        $str02 = "*** in database %s ***" ascii
        $str03 = "\\drivers\\etc\\HOSTS" ascii
        $str04 = "Babylon RAT Client" wide
        $str05 = "ClipBoard.txt" wide
        $str06 = "a,ccs=UTF-16LE" wide
        $str07 = "[%02d/%02d/%d %02d:%02d:%02d] [%s] (%s):" wide
        $str08 = "Update Failed [OpenProcess]..." wide
        $str09 = "DoS Already Active..." wide
        $str10 = "File Download and Execution Failed..." wide
        $str11 = "LgDError33x98dGetProcAddress" wide
        $str12 = "FriendlyName" wide
        $str13 = "@SPYNET" wide
        
    condition:
        uint16(0) == 0x5a4d and 8 of ($str*)
}
        