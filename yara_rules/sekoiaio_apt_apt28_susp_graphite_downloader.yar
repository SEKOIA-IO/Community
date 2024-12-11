import "pe"
        
rule sekoiaio_apt_apt28_susp_graphite_downloader {
    meta:
        id = "9c9da5fe-ffd6-4c45-8ce1-9a6cf4fa2fda"
        version = "1.0"
        description = "Matches the routine which decrypts the RSA key blob in the Graphite downloader"
        source = "Sekoia.io"
        creation_date = "2022-01-26"
        classification = "TLP:CLEAR"
        
    strings:
        $gen =  { 33 D2
        8B C1
        6A ??
        5E
        F7 F6
        8A 82 ?? ?? ?? ??
        30 81 ?? ?? ?? ??
        41
        81 F9 94 04 00 00
        72 E2 }
        
    condition:
        uint16be(0) == 0x4d5a and $gen and pe.number_of_exports == 1
}
        