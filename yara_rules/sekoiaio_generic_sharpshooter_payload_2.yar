rule sekoiaio_generic_sharpshooter_payload_2 {
    meta:
        id = "02bc795f-b8e0-44d4-b475-310359867577"
        version = "1.0"
        description = "Detects payload created by SharpShooter"
        source = "Sekoia.io"
        creation_date = "2023-02-03"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "var e={},i,b=0,c,x,l=0,a,r="
        $ = "eval(plain);"
        $ = "var plain = rc4("
        
    condition:
        all of them and filesize < 2MB
}
        