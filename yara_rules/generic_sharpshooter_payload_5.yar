rule generic_sharpshooter_payload_5 {
    meta:
        id = "cb4d266e-f2b7-4642-a223-57180e66a9a6"
        version = "1.0"
        description = "Detects payload created by SharpShooter"
        author = "Sekoia.io"
        creation_date = "2023-02-03"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "rc4 = function(key, str)"
        $ = "<job id=\"JS Code\""
        $ = "var e={},i,b=0,c,x,l=0,a,r="
        $ = "var plain = rc4("
        $ = "eval(plain);"
        
    condition:
        all of them and filesize < 2MB
}
        