rule sekoiaio_apt_oilrig_oilbooster_strings {
    meta:
        id = "001d12bc-1e7e-4a6c-9172-66687d08d827"
        version = "1.0"
        description = "Detects OilBooster malware based on strings"
        source = "Sekoia.io"
        creation_date = "2023-12-20"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "/rt.ovf" wide ascii
        $ = "User-Agent: " wide ascii
        $ = "/me/drive/items" wide ascii
        $ = "client_secret" wide ascii
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 5MB and
        all of them
}
        