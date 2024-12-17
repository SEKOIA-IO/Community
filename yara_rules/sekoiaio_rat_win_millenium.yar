rule sekoiaio_rat_win_millenium {
    meta:
        version = "1.0"
        description = "Finds MilleniumRAT samples based on the specific strings"
        author = "Sekoia.io"
        creation_date = "2023-11-16"
        id = "91320924-5c74-457a-8601-29c4e4034761"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "Millenium RAT, version:" wide
        $str02 = "Coded by @shinyenigma" wide
        $str03 = "*gift*<NEW TOKEN>*<NEW CHAT ID>*<message> - gift this bot to another user, his telegram bot has to be started" wide
        $str04 = "*historyForce - grab more browser history by killing browser processes, use carefully" wide
        $str05 = "*download - victim`s PC downloads a file attached to this message, if it is a picture it should also be attached as a file" wide
        $str06 = "No keylogs recorded!" wide
        $str07 = "Successfully added RAT to startup" wide
        $str08 = "You`ve gifted gifted a bot:" wide
        $str09 = "Incorrect agrument, please enter 0/90/180/270" wide
        $str10 = "SELECT action_url, username_value, password_value FROM logins" wide
        $str11 = "Yandex\\YandexBrowser\\User Data\\Default" wide
        
        $str12 = "Millenium-rat-CSharp (main project)" ascii
        $str13 = "get_BatteryLifePercent" ascii
        $str14 = "get_ExpirationMonth" ascii
        $str15 = "sqlite3_extension_init " ascii
        
    condition:
        uint16(0)==0x5A4D and 10 of ($str*)
}
        