rule backdoor_win_feedload {
    meta:
        id = "29cc46c4-7ed7-4a34-9749-a8ba8d37eb4c"
        version = "1.0"
        author = "Sekoia.io"
        creation_date = "2023-10-24"
        classification = "TLP:CLEAR"
        hash = "f251144f7ad0be0045034a1fc33fb896e8c32874e0b05869ff5783e14c062486"
        
    strings:
        $s1 = "                                        C:\\LibreSS5\\crypto\\"
        
    condition:
        uint16be(0)==0x4d5a and #s1 > 200
}
        