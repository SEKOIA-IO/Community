rule sekoiaio_ransomware_win_masons_jan2023 {
    meta:
        id = "cf2af08b-b4a8-4245-9308-242e15aeb346"
        version = "1.0"
        description = "Rule to detect Masons ransomware samples."
        source = "Sekoia.io"
        creation_date = "2023-02-13"
        classification = "TLP:CLEAR"
        hash1 = "7826978642c568f975e2b65d1575fdf92e634f7c80db2c86c9d7c8066e8955b8"
        
    strings:
        $s1 = "Masons" wide
        $s2 = "@mineralIaha/@root_king1" wide
        $s3 = "Glory @six62ix" wide
        
    condition:
        uint16be(0) == 0x4d5a and all of them
}
        