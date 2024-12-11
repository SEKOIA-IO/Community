rule sekoiaio_infostealer_win_stormkitty_exfil_urls {
    meta:
        id = "d3b6e778-85da-4ab6-bc98-921897677485"
        version = "1.0"
        description = "Detect the open-source StormKitty spyware by looking for the github path"
        source = "Sekoia.io"
        creation_date = "2022-04-20"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "https://github.com/LimerBoy/StormKitty" ascii
        $telegram = "https://api.telegram.org" wide
        $discord = "https://cdn.discordapp.com" wide
        
    condition:
        uint16(0)==0x5A4D
        and all of them
        and (#telegram > 3 or #discord > 3)
}
        