rule apt_gamaredon_lnk_spreader {
    meta:
        id = "2866ca1d-c094-49ba-b1de-ff9a60680e28"
        version = "1.0"
        description = "Detects LNK generated by Gamaredon LNK spreader"
        author = "Sekoia.io"
        hash = "7d6264ce74e298c6d58803f9ebdb4a40b4ce909d02fd62f54a1f8d682d73519a"
        creation_date = "2023-06-19"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "windoWSTYLE hiDdEn -NOlOgo iEX" wide nocase
        $ = "(IeX (geT-coNtEnT" wide nocase
        
    condition:
        uint32be(0) == 0x4C000000 
        and filesize < 3KB
        and all of them
}
        