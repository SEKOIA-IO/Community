rule sekoiaio_rat_lin_gobrat_2023 {
    meta:
        id = "ca36a586-f87f-445f-95dc-52d447c1d2a2"
        version = "1.0"
        description = "This rule detect samples that are downloaded on the GobRAT C2 URL path /a, /b and /c."
        source = "Sekoia.io"
        creation_date = "2023-06-09"
        classification = "TLP:CLEAR"
        hash1 = "36cb17d9d118bd9692106c8aafab2462aacf1cdad3a6afb0e4f1de898a7db0e1"
        hash2 = "28a714f7cec4445dbd507b85016c8e96ed5e378bcabe2e422c499975122b3f03"
        hash3 = "1e80a084ab89da2375bc3cc2f5a37975edff709ef29a3fa2b4df4ccb6d5afe10"
        
    strings:
        $s1 = "Z:/Go/awesomeProject3/main.go" wide ascii
        
    condition:
        uint32(0)==0x464c457f
        and filesize < 4000KB
        and $s1
}
        