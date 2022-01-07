import "pe"
rule apt_nobelium_cs_loader_obfuscation {
    meta:
        id = "5f21b031-3dc1-4dad-b775-6099bfcb0472"
        version = "1.0"
        description = "Detect obfuscated CobaltStrike loaders used by NOBELIUM"
        hash = "41dd8cee47c036e7e9e92c395c5d1feb"
        hash = "4365057ef0c5a9518d95d53eab5995a8"
        source = "SEKOIA"
        creation_date = "2022-01-04"
        modification_date = "2022-01-04"
        classification = "TLP:WHITE"
    strings:
        $j1 = { DD 05 ?? ?? ?? ?? DD 9D }
        $j2 = { C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 }
        $c1 = { 81 7D ?? FF 00 00 00 0F 8E ?? ?? FF FF }
    condition:
        pe.characteristics & pe.DLL and
        pe.number_of_exports > 20 and 
        filesize > 300KB and filesize < 400KB and
        #j1 > 50 and #j2 > 50 and #c1 == 2
 }
