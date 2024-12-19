rule apt_implant_xdealer_stealer_strings {
    meta:
        id = "6314cf6c-2c3b-4e9a-87a1-b56ee148474c"
        version = "1.0"
        description = "Detects stealer module of XDealer"
        author = "Sekoia.io"
        creation_date = "2024-03-22"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "%sbmp.tmp"
        $ = "%sjgp.tmp"
        $ = "%sma_%s_%05u_%u."
        $ = "%s%s_%05u_%u."
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 500KB and
        all of them
}
        