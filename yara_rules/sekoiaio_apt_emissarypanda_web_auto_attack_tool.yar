rule sekoiaio_apt_emissarypanda_web_auto_attack_tool {
    meta:
        id = "c93eb792-a443-4c9a-8fcb-6015cc69f9b3"
        version = "1.0"
        description = "Detect LuckyMouse's Web auto attack tool"
        source = "Sekoia.io"
        creation_date = "2022-08-03"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[192.168.1.1/24|192.168.1.1|192.168.1|@host.txt]" ascii
        $ = "80,s443,8080,s8443,8000-8010" ascii
        $ = "exploit When find module vul" ascii
        $ = "<title>\\s*(.*?)\\s*</title>" ascii
        $ = "<meta.+?charset=[^\\w]?([-\\w]+)" ascii
        $ = "%s is not existed" ascii
        $ = "%-15s %4d Open" wide
        
    condition:
        uint16be(0) == 0x4d5a and 4 of them and filesize < 500KB
}
        