rule builder_win_royalroad_rtf {
    meta:
        id = "065e798b-eadd-4aac-a444-de61b75f0273"
        description = "Detects RoyalRoad weaponized RTF documents"
        creation_date = "2022-06-23"
        author = "Sekoia.io"
        version = "1.0"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "{\\object\\objocx{\\objdata"
        $ = "ods0000"
        
    condition:        uint32be(0) == 0x7B5C7274 and all of them
}
        