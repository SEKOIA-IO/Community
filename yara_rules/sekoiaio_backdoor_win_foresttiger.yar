rule sekoiaio_backdoor_win_foresttiger {
    meta:
        id = "d3128da2-a86d-4db8-9b75-2f3048831c7e"
        version = "1.0"
        description = "Detect Lazarus' malware ForestTiger"
        source = "Sekoia.io"
        creation_date = "2023-10-24"
        classification = "TLP:CLEAR"
        hash1 = "e06f29dccfe90ae80812c2357171b5c48fba189ae103d28e972067b107e58795"
        hash2 = "0be1908566efb9d23a98797884f2827de040e4cedb642b60ed66e208715ed4aa"
        reference = "https://www.microsoft.com/en-us/security/blog/2023/10/18/multiple-north-korean-threat-actors-exploiting-the-teamcity-cve-2023-42793-vulnerability/"
        
    strings:
        $ = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edg/107.0.1418.42"
        $ = "biwbih="
        $ = "rlzbiw="
        $ = "whoami EnDePriv Erro" wide
        
    condition:
        uint16be(0) == 0x4d5a and all of them
}
        