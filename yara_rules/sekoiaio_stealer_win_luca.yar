import "pe"
        
rule sekoiaio_stealer_win_luca {
    meta:
        id = "d2cc1442-0ba5-4e81-9fea-e9e078903eed"
        version = "1.0"
        description = "Detect Luca stealer. Open source Rust stealer."
        source = "Sekoia.io"
        creation_date = "2022-07-26"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "cookies"
        $ = "creditcards"
        $ = "/Default/Network/CookiesUser Data/Default/Network/Cookies_cookies"
        $ = "/Default/Web DataUser Data/Default/Web Data_webdata"
        $ = "SELECT action_url, username_value, password_value FROM loginsSELECT card_number_encrypted, name_on_card, expiration_month, expiration_year FROM credit_cardsSELECT host_key, name, encrypted_value, path, expires_utc, is_secure FROM cookiesLOCALAPPDATA"
        $ = "\\logsxc\\passwords_.txt"
        $ = " Name:"
        $ = "User: "
        $ = "Installed Languages:  "
        $ = "Operating System: "
        $ = "Used/Installed RAM:  GB "
        $ = "Cores available: "
        $ = "\\screen-.png"
        $ = "Username: "
        $ = "Computer name: "
        $ = "OS: "
        $ = "Language: "
        $ = "Hostname: "
        $ = "=> networks: B"
        $ = "=> system:total memory:  KB"
        $ = "used memory : "
        $ = "total swap  : "
        $ = "used swap   : "
        $ = "NB CPUs: "
        $ = "Passwords: "
        $ = "Wallets: "
        $ = "Files: "
        $ = "Credit Cards: "
        $ = "sensfiles.zip"
        
    condition:
        uint16(0)==0x5A4D
        and filesize > 4000KB
        and pe.rich_signature.toolid(0, 0)
        and pe.number_of_resources == 0
        and 15 of them
}
        