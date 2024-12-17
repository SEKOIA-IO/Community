rule sekoiaio_radx_stealer {
    meta:
        id = "bf2aae08-169c-4bc9-a1ac-80f4b79ef6d7"
        version = "1.0"
        description = "detection of RADX stealer based on function named in the .NET payload"
        author = "Sekoia.io"
        creation_date = "2023-12-22"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "get_FileName" ascii fullword
        $s2 = "set_FileName" ascii fullword
        $f1 = "TripleDESCryptoServiceProvider" ascii fullword
        $f2 = "SendBase64ToServer" ascii fullword
        $f3 = "SendCommandOutputToServer" ascii fullword
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize > 500KB and all of them
}
        