rule sekoiaio_apt_evasive_panda_rphost_dll {
    meta:
        id = "8d70639d-b736-4823-86ad-37f0e383b5f7"
        version = "1.0"
        description = "Detects DLL used by Evasive Panda"
        source = "Sekoia.io"
        creation_date = "2024-03-15"
        classification = "TLP:CLEAR"
        hash = "fa44028115912c95b5efb43218f3c7237d5c349f"
        
    strings:
        $s1 = "htks.ini" ascii fullword
        $s2 = "MyDemo" wide fullword
        
    condition:
        uint16be(0) == 0x4d5a and 
        all of them 
        
        and filesize < 1MB
}
        