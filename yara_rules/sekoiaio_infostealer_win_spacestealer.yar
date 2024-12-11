rule sekoiaio_infostealer_win_spacestealer {
    meta:
        version = "1.0"
        description = "Detects SpaceStealer based on specific strings"
        source = "Sekoia.io"
        creation_date = "2022-11-29"
        id = "aceae3b3-1f5a-48b4-84cb-d0ba68d26df5"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "spacestealerxD" ascii
        $str02 = "\\spacex" ascii
        $str03 = "@~$~@spacex-" ascii
        $str04 = "StealerClient" ascii
        $str05 = "kill-process-by-name" ascii
        $str06 = "\\BetterDiscord\\data\\betterdiscord.asar" ascii
        $str07 = "api/webhooks" ascii
        $str08 = "discordPath" ascii
        $str09 = "SELECT host_key, name, encrypted_value FROM cookies" ascii
        $str10 = "SELECT origin_url, username_value, password_value FROM logins" ascii
        $str11 = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards" ascii
        $str12 = "Cookies don't found." ascii
        $str13 = "/api/cookies?auth=" ascii
        $str14 = "/api/passwords?auth=" ascii
        $str15 = "/api/autofill?auth=" ascii
        $str16 = "/api/creditcards?auth=" ascii
        $str17 = "\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\Network\\" ascii
        
    condition:
        uint16(0) == 0x5A4D and filesize > 10MB and 13 of them
}
        