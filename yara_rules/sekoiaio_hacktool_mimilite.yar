rule sekoiaio_hacktool_mimilite {
    meta:
        id = "abb92a9d-0978-4ef2-b2cc-53ce6e83e3e4"
        version = "1.0"
        description = "Detects Mimilite"
        source = "Sekoia.io"
        creation_date = "2023-12-05"
        classification = "TLP:CLEAR"
        
    strings:
        $chunk = {
        FF C7
        48 63 D7
        46 0F B6 04 22
        41 03 F0
        81 E6 ?? ?? ?? ??
        7D ??
        FF CE
        81 CE ?? ?? ?? ??
        FF C6
        48 63 CE
        42 0F B6 04 21
        42 88 04 22
        46 88 04 21 }
        $imp1 = "CryptGetHashParam"
        $imp2 = "CryptDestroyHash"
        $imp3 = "CryptHashData"
        $imp4 = "CryptReleaseContext"
        $imp5 = "CryptCreateHash"
        $imp6 = "CryptAcquireContextA"
        $imp7 = "VirtualAlloc"
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 200KB and
        all of ($imp*) and $chunk
}
        