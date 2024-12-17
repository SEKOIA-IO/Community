rule sekoiaio_apt_andariel_siennablue {
    meta:
        id = "ab3f8b49-0851-47a8-ac77-98d4e26f448e"
        version = "1.0"
        description = "Detects SiennaBlue based routine names"
        author = "Sekoia.io"
        creation_date = "2023-11-16"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "main_cryptAVPass"
        $ = "main_DecryptString"
        $ = "main_DisableNetworkDevice"
        $ = "main_DeleteSchTask"
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize > 4MB and filesize < 15MB and
        all of them
}
        