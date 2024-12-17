rule sekoiaio_infostealer_win_enigma_stealer_module {
    meta:
        id = "664fe8de-b406-4d63-9a4b-1c350b444f02"
        version = "1.0"
        description = "Find stealer module of Enigma Stealer based on specific strings"
        author = "Sekoia.io"
        creation_date = "2023-01-30"
        classification = "TLP:CLEAR"
        hash = "4d2fb518c9e23c5c70e70095ba3b63580cafc4b03f7e6dce2931c54895f13b2c"
        
    strings:
        $eni01 = "enigma.common" nocase ascii wide
        $eni02 = "--ENIGMA STEALER--" wide
        
        $str01 = "SELECT * FROM Win32_PnPEntity WHERE (PNPClass = 'Image' OR PNPClass = 'Camera')" wide
        $str02 = "/C chcp 65001 && netsh wlan show profile | findstr All" wide
        $str03 = "/C chcp 65001 && netsh wlan show networks mode=bssid" wide
        $str04 = "[Open google maps]" wide
        $str05 = "Stealerium.Target." ascii
        $str06 = "--- ClipperBCH ---" wide
        $str07 = "//setting[@name='Username']/value" wide
        $str08 = "Stealer >> Failed recursive remove directory with passwords" wide
        $str09 = "[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_\\-]{27}|mfa\\.[a-zA-Z0-9_\\-]{84}" wide //Discord Token regex
        $str10 = "^(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}$" wide //Maestro Card regex
        
    condition:
        uint16(0)==0x5A4D and 1 of ($eni*) and 4 of ($str*)
}
        