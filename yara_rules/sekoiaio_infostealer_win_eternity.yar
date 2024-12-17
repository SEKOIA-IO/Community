import "pe"
        
rule sekoiaio_infostealer_win_eternity {
    meta:
        id = "0ed8d4bd-d57f-40a8-a709-d69531d59847"
        version = "1.0"
        description = "Detect the Eternity infostealer based on specific strings"
        author = "Sekoia.io"
        reference = "hxxp://xssforumv3isucukbxhdhwz67hoa5e2voakcfkuieq4ch257vsburuid.]onion/threads/62331/"
        creation_date = "2022-03-23"
        classification = "TLP:CLEAR"
        
    strings:
        $str0 = "Sending info to Eternity.." wide
        $str1 = "Debug mode, dont share this stealer anywhere." wide
        $str2 = "\\Growtopia.exe" wide
        $str3 = "Software\\Growtopia" wide
        $str4 = "Corrupting Growtopia.." wide
        $str5 = "Disabling Task Manager.." wide
        $str6 = "Deleting previous file from startup and copying new one." wide
        $str7 = "Hiding file in Startup folder.." wide
        $str8 = "Initializing File watcher.." wide
        $str9 = "Decoder: Failed to delete temp login. No problem, continuing.." wide
        $str10 = "dcd.exe" wide
        
    condition:
        uint16(0)==0x5A4D and
        (for any i in (0..pe.number_of_sections-1) : ( pe.sections[i].name == ".eter0" ) and
        for any i in (0..pe.number_of_sections-1) : ( pe.sections[i].name == ".eter1" )) or 
        4 of ($str*)
}
        