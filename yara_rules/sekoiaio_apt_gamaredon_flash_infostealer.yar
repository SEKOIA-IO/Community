rule sekoiaio_apt_gamaredon_flash_infostealer {
    meta:
        id = "f060fe4b-74fd-4ef3-ac86-916e2113ff24"
        version = "1.0"
        description = "Detects the Gamaredon's Flash InfoStealer"
        author = "Sekoia.io"
        creation_date = "2023-01-24"
        classification = "TLP:CLEAR"
        
    strings:
        $a1 = "Content-Type: multipart/form-data; boundary=----%s" ascii
        $a2 = "Content-Disposition: form-data; name=\"p\"" ascii
        $a3 = "Content-Type: application/octet-stream"
        $w1 = "%s||%s||%s||%s" wide
        $w2 = "Pragma: no-cache" wide
        $w3 = { 64 00 6F 00 63 00 00 00 00 00 2E 00 64 00 6F 00 63 00 78 00 }
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 500KB and
        2 of ($a*) and 2 of ($w*)
}
        