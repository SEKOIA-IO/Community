rule sekoiaio_infostealer_win_banditstealer {
    meta:
        id = "d1e45a5c-c06d-4161-8d30-fa94bcf0ea7a"
        version = "1.0"
        description = "Finds BanditStealer samples based on specific strings"
        author = "Sekoia.io"
        creation_date = "2023-07-03"
        classification = "TLP:CLEAR"
        
    strings:
        $spe01 = "Banditstealer" ascii
        $spe02 = "BANDIT STEALER" ascii
        $spe03 = "Location: Geolocation: " ascii
        $spe04 = "awesomeProject2/core.GetWallets" ascii
        $spe05 = "awesomeProject2/core.GetCreditCards" ascii
        $spe06 = "awesomeProject2/core.GetCookies" ascii
        $spe07 = "awesomeProject2/core.KillProcessByName" ascii
        $spe08 = "main.sendZipToTelegram" ascii
        
        $str01 = "json:\"city\"" ascii
        $str02 = "UAC disabled" ascii
        $str03 = "\\OpenVPN Connect\\profiles\\" ascii
        $str04 = "\\Documents\\Monero\\wallets\\" ascii
        $str05 = "cookies.sqlite" ascii
        $str06 = "creditcard.txt" ascii
        $str07 = "vmware.exe" ascii
        $str08 = "aeachknmefphepccionboohckonoeemg" ascii
        $str09 = "\\Documents\\NetSarang\\Xftp\\Sessions\\" ascii
        $str10 = "\\WhatsApp\\Local Storage\\leveldb\\" ascii
        $str11 = "Visited Time: %s" ascii
        $str12 = "\\Google\\Chrome\\User Data\\Telegram Desktop\\tdata\\" ascii
        
    condition:
        uint16(0) == 0x5a4d and 2 of ($spe*) and 6 of ($str*)
}
        