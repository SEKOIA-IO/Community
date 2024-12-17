rule sekoiaio_loader_win_bumblebee {
    meta:
        id = "ff36f512-c700-4f52-bc89-68ab9c69462c"
        version = "1.0"
        description = "Detect BUMBLEBEE based on specific strings"
        author = "Sekoia.io"
        creation_date = "2022-04-08"
        classification = "TLP:CLEAR"
        
    strings:
        $str0 = "Z:\\hooker2\\Common\\md5.cpp" wide
        $str1 = "3C29FEA2-6FE8-4BF9-B98A-0E3442115F67" wide
        $str2 = "bumblebee" ascii
        
    condition:
        uint16(0)==0x5A4D and 2 of them
}
        