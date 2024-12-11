rule sekoiaio_apt_lazarus_vhd_ransomware_loader {
    meta:
        id = "377f3ec5-fa2a-431e-93d2-6a1eb9e01d28"
        version = "1.0"
        description = "Detects VHD ransomware x64 loader "
        source = "Sekoia.io"
        creation_date = "2022-11-28"
        classification = "TLP:CLEAR"
        
    strings:
        $ = { B8 64 [8] B8 75 [8] B8 6D [8] B8 70 [8] B8 2E [8] B8 62 [8] B8 69 [8] B8 6E }
        $ = { 48 63 ?? ?? ??
        48 8B ?? ?? ??
        0F BE ?? ??
        B9 ?? ?? ?? ??
        48 6B ?? ??
        48 8B ?? ?? ??
        0F BE ?? ??
        ?? ??
        48 63 ?? ?? ??
        48 8B ?? ?? ??
        88 ?? ??
        EB }
        $ = { 25 00 73 00 5c [3-15] 25 00 64 00 25 00 64 00 2e 00 62 00 69 00 6e }
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 200KB and
        2 of them
}
        