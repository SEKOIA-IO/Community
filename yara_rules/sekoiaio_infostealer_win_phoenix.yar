rule sekoiaio_infostealer_win_phoenix {
    meta:
        id = "d63a8fcf-f897-4c36-a6ce-4bd4ae0154e5"
        version = "1.0"
        description = "Finds Phoenix Stealer samples based on specific strings"
        source = "Sekoia.io"
        creation_date = "2023-06-20"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii
        $str02 = "Discord\\Tokens.txt" ascii
        $str03 = "SOFTWARE\\OpenVP" ascii
        $str04 = "config_dir" ascii
        $str05 = "| Last Login:" ascii
        $str06 = "| Games:" ascii
        $str07 = "| Host:" ascii
        $str08 = "| Port:" ascii
        $str09 = "| User:" ascii
        $str10 = "| Pass:" ascii
        $str11 = "Grabber.rar" ascii
        $str12 = "\\GHISLER\\wcx_ftp.ini" ascii
        $str13 = "Clipboard.txt" ascii
        $str14 = "PROCESSOR_ARCHITECTURE" ascii
        $str15 = "PROCESSOR_IDENTIFIER" ascii
        $str16 = "Log.txt" ascii
        $str17 = "xXxXxXxXxXx" ascii
        $str18 = "hq101ejedmwcvvasd02kw" ascii
        
    condition:
        uint16(0) == 0x5a4d and 15 of them 
        and filesize > 500KB
}
        