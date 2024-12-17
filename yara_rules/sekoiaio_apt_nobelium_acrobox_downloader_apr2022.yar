rule sekoiaio_apt_nobelium_acrobox_downloader_apr2022 {
    meta:
        id = "77f7f01d-72a2-4b13-b23f-d938a415dd40"
        version = "1.0"
        description = "Detects AcroBox downloader"
        author = "Sekoia.io"
        creation_date = "2022-05-11"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = { 80 ?? 7B
        0F 84 ?? ?? 00 00
        80 ?? ?? 0F
        0F 84 ?? ?? 00 00
        80 ?? ?? 0F
        0F 84 ?? ?? 00 00
        80 ?? ?? 0F
        0F 84 ?? ?? 00 00 }
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 200KB and
        all of ($s*)
}
        