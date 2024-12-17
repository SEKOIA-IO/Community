rule sekoiaio_loader_amadey_stealer_plugin {
    meta:
        version = "1.0"
        description = "Finds Amadey's stealer plugin based on characteristic strings"
        author = "Sekoia.io"
        creation_date = "2023-05-16"
        id = "50154e39-98b3-40e5-8986-18bbb7b15647"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "STEALERDLL.dll" ascii
        $str02 = "?wal=1" fullword ascii
        $str03 = "Content-Disposition: form-data; name=\"data\"; filename=\"" ascii
        $str04 = "tar.exe -cf \"" ascii
        $str05 = "SELECT origin_url, username_value, password_value FROM logins" ascii
        $str06 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii
        $str07 = "\\SputnikLab\\Sputnik\\User Data\\Default\\Login Data" ascii
        $str08 = "\\Mozilla\\Firefox\\Profiles\\" ascii
        $str09 = "\"hostname\":\"([^\"]+)\"" ascii
        $str10 = "\"encryptedUsername\":\"([^\"]+)\"" ascii
        $str11 = "\"encryptedPassword\":\"([^\"]+)\"" ascii
        $str12 = "&cred=" fullword ascii
        $str13 = "D:\\Mktmp\\Amadey\\StealerDLL\\x64\\Release\\STEALERDLL.pdb" ascii
        
    condition:
        uint16(0)==0x5A4D and 7 of them
}
        