rule sekoiaio_koi_koiloader {
    meta:
        id = "b8289d78-42de-4919-b2c5-3c926ddd8043"
        version = "1.0"
        description = "Detects Koi Loader"
        source = "Sekoia.io"
        creation_date = "2024-03-20"
        classification = "TLP:CLEAR"
        
    strings:
        $s2 = "%d|%s|%.16s|" ascii wide
        $s3 = "Release" ascii wide
        $s4 = "%s|%d.%d (%d)|%S|%S|%S" ascii wide
        $s5 = "InitiateSystemShutdownExW" ascii wide
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 11MB and
        all of them
}
        