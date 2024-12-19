rule tool_godpotato {
    meta:
        id = "cc396771-f187-43ae-903f-147d15483c46"
        version = "1.0"
        author = "Sekoia.io"
        creation_date = "2023-08-23"
        classification = "TLP:CLEAR"
        author = "Sekoia.io"
        
    strings:
        $s1 = "[!] Cannot create process Win32Error:{0}" ascii wide
        $s2 = "[*] process start with pid {0}" ascii wide
        $s3 = "MEOW" ascii wide
        $s4 = "2ae886c3-3272-40be-8d3c-ebaede9e61e1" ascii wide
        $s5 = "GodPotatoUnmarshalTrigger" ascii wide
        $s6 = "GodPotato.exe" ascii wide
        $s7 = "GodPotato.exe" wide
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 4MB and 
        all of them
}
        