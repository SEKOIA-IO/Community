rule sekoiaio_infostealer_win_xenostealer_strings {
    meta:
        id = "0a41788b-1fa7-44ff-af85-9c1ff1892aad"
        version = "1.0"
        description = "Finds XenoStealer standalone samples based on the strings"
        author = "Sekoia.io"
        reference = "https://github.com/moom825/XenoStealer/"
        creation_date = "2024-10-30"
        classification = "TLP:CLEAR"
        hash = "b74733d68e95220ab0630a68ddf973b0c959fd421628e639c1b91e465ba9299b"
        
    strings:
        $str01 = "XenoStealer" ascii wide
        $str02 = "$d05de59c-9ee5-4e7e-abb5-8f2cc3f72cd1" ascii
        $str03 = "SteamInfo" ascii
        $str04 = "TelegramInfo" ascii
        $str05 = "NgrokInfo" ascii
        $str06 = "pAuthInfo" ascii
        $str07 = "FoxMailInfo" ascii
        $str08 = "_hasNitro" ascii
        $str09 = "_games" ascii
        $str10 = "_profiles" ascii
        $str11 = "_cookies" ascii
        $str12 = "_creditCards" ascii
        $str13 = "_cryptoExtensions" ascii
        $str14 = "_passwordManagerExtensions" ascii
        $str15 = "ChromiumBrowsersLikelyLocations" ascii
        $str16 = "EdgeCryptoExtensions" ascii
        $str17 = "ChromePasswordManagerExtensions" ascii
        $str18 = "GeckoBrowserOptions" ascii
        $str19 = "get_programFiles" ascii
        
    condition:
        uint16(0)==0x5A4D and 15 of them
}
        