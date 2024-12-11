import "pe"
        
rule sekoiaio_infostealer_win_metastealer_strings {
    meta:
        id = "1f4b6f0b-706e-48b0-889d-01c1b7f92776"
        version = "1.0"
        description = "Detects IOCs related to Metastealer"
        source = "Sekoia.io"
        creation_date = "2023-12-13"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "FileScannerRule"
        $s2 = "MSObject"
        $s3 = "MSValue"
        $s4 = "GetBrowsers"
        $s5 = "Biohazard"
        
    condition:
    4 of ($s*) 
    and pe.imports("mscoree.dll")
}
        