rule sekoiaio_lnk_astaroth {
    meta:
        id = "1f4ce619-6f94-400a-9b32-46f2018da25c"
        version = "1.0"
        description = "Astaroth LNK"
        source = "Sekoia.io"
        creation_date = "2024-09-18"
        classification = "TLP:CLEAR"
        hash = "5611ea372f63ccd3a2e860e763714bb9"
        hash = "3e4c01180fd7e9bffbf5cc9fe9e9c8ae"
        hash = "ce4a3cfc450a8bbf8399c71d67c09954"
        
    strings:
        $all1 = "S-1-5-21-" wide
        $all2 = "..\\..\\Windows\\System32\\cmd.exe" wide
        
        $ver2_1 = "&&<nul" wide
        $ver2_2 = "|call !" wide
        $ver2_3 = "\\shell32.dll" wide
        $ver2_4 = ";eval(" wide
        $ver2_5 = "\\u" wide
        
        $ver1_1 = "/c mshtA \"JaVAsCrIpT:" nocase wide
        $ver1_2 = "}catch(" nocase wide
        $ver1_3 = "){}" nocase wide
        $ver1_4 = "close()" nocase wide
        $ver1_5 = "\\x" wide
        $ver1_6 = "\\1" wide
        
    condition:
        uint32be(0) == 0x4c000000 and filesize<3KB and all of ($all*) and
        ((all of ($ver2*) and #ver2_5 > 20) or (all of ($ver1*) and #ver1_5 > 20 and #ver1_6 > 7))
}
        