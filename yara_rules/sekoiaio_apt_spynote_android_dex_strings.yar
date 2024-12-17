rule sekoiaio_apt_spynote_android_dex_strings {
    meta:
        id = "87fb8b7a-bfac-4003-b618-50b4a7863928"
        version = "1.0"
        description = "Detects Android SpyNote DEX file"
        author = "Sekoia.io"
        creation_date = "2022-08-22"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "is not file found"
        $ = "Can not access"
        $ = "PANG !!"
        $ = "On Start!!"
        
    condition:
        uint32be(0) == 0x6465780A and
        filesize < 1MB and
        all of them
}
        