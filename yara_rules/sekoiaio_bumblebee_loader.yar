rule sekoiaio_bumblebee_loader {
    meta:
        id = "8fd795c7-6896-498c-a892-de9da6427b60"
        version = "1.0"
        description = "Detect the BUMBLEBEE loader"
        author = "Sekoia.io"
        creation_date = "2022-05-23"
        classification = "TLP:CLEAR"
        
    strings:
        $str0 = { 5a 00 3a 00 5c 00 68 00 6f 00 6f 00 6b 00 65 00 72 00 32 00 5c 00 43 00 6f 00 6d 00 6d 00 6f 00 6e 00 5c 00 6d 00 64 00 35 00 2e 00 63 00 70 00 70 00 }
        $str1 = "/gate" ascii
        $str2 = "3C29FEA2-6FE8-4BF9-B98A-0E3442115F67" wide
        $str3 = "BLACK" ascii
        
    condition:
        uint16be(0) == 0x4d5a and 3 of them
}
        