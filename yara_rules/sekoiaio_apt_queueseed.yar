rule sekoiaio_apt_queueseed {
    meta:
        id = "35f7ffd5-4f6f-4b31-8d60-c713a15d14e8"
        version = "1.0"
        description = "Detects strings of Queueseed/Kapeka malware"
        author = "Sekoia.io"
        creation_date = "2024-04-22"
        classification = "TLP:CLEAR"
        
    strings:
        // Looking for strings with alignment
        $ = {2D 00 6F 00 00 00} // '-o'
        $ = {2D 00 62 00 63 00 00 00} //'-bc'
        $ = {20 00 00 00 00 00 00 00} // ' '
        $ = {20 00 2D 00 77 00 00 00} // ' -w'
        $ = {35 00 3A 00 20 00 00 00} // '5: '
        $ = {34 00 3A 00 20 00 00 00} // '4: '
        $ = {33 00 3A 00 20 00 00 00} // '3: '
        $ = {32 00 3A 00 20 00 00 00} // '2: '
        $ = {31 00 3A 00 20 00 00 00} // '1: '
        $ = {50 00 49 00 44 00 20 00 3A 00 20 00 00 00 00 00} // 'PID : '
        
        
        $ = "ExitCode : " wide
        
    condition:
        uint16be(0) == 0x4d5a and all of them and filesize < 200KB
}
        