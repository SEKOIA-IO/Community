rule sekoiaio_apt_luckymouse_sysupdate_removing_tool {
    meta:
        id = "711d059c-6229-49ef-aa20-a04d505838dc"
        version = "1.0"
        description = "Detects the SysUpdate removing tool"
        author = "Sekoia.io"
        creation_date = "2022-08-03"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "KsWAYYYXXsFUCK" wide
        $ = "remove Services:%s %d" wide
        $ = "remove dir:%s %d" wide
        $ = "remove reg %d" wide
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 11MB and 2 of them
}
        