rule generic_sharpshooter_payload_1 {
    meta:
        id = "82fd284a-47c2-4d29-9c80-f3affaa61a13"
        version = "1.0"
        description = "Detects payload created by SharpShooter"
        author = "Sekoia.io"
        creation_date = "2023-02-03"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "rc4 = function(key, str)"
        $ = "var e={},i,b=0,c,x,l=0,a,r="
        $ = "var plain = rc4("
        $ = "<script language="
        
    condition:
        all of them and filesize < 2MB
}
        