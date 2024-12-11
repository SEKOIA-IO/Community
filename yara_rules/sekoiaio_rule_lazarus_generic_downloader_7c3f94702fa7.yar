rule sekoiaio_rule_lazarus_generic_downloader_7c3f94702fa7 {
    meta:
        id = "eb0f0a91-5e72-4358-91a3-7c3f94702fa7"
        version = "1.0"
        description = "Detects a Generic Downloader used by Lazarus"
        source = "Sekoia.io"
        creation_date = "2022-08-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "%s%s%s%s = %s%s%s%s"
        $ = "sec-ch-ua-mobile: ?0"
        $ = "%s>%s"
        $ = "d$f92&^$#FESAfaSDage#FDa"
        $ = "Sec-Fetch-User: ?1"
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 200KB and
        3 of them
}
        