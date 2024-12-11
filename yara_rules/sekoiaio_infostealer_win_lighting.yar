rule sekoiaio_infostealer_win_lighting {
    meta:
        id = "3c160c16-f417-4fa2-aa44-fb7b981fb2b3"
        version = "1.0"
        description = "Detect the Lighting infostealer based on specific strings"
        source = "Sekoia.io"
        reference = "https://blog.cyble.com/2022/04/05/inside-lightning-stealer/"
        creation_date = "2022-04-07"
        classification = "TLP:CLEAR"
        
    strings:
        $str0 = "\\logins.json" wide
        $str1 = "key3.db" wide
        $str2 = "\\key4.db" wide
        $str3 = "cert9.db" wide
        $str4 = "\\places.sqlite" wide
        $str5 = "7D78CB380BF5EFB7B851409CA6A875F77DECF09D19B9149DA17A3EBF674BC0F9" ascii
        $str6 = "potentiallyVulnerablePasswords" wide
        
        $dll0 = "\\mozglue.dll" wide
        $dll1 = "\\nss3.dll" wide
        $dll2 = "SbieDll.dll" wide
        
        $app00 = "\\discord\\Local Storage\\leveldb\\" wide
        $app01 = "Software\\Valve\\Steam" wide
        $app02 = "Telegram Desktop\\tdata" wide
        $app03 = "\\Wallets\\Armory\\" wide
        $app04 = "\\Wallets\\Atomic\\Local Storage\\leveldb\\" wide
        $app05 = "\\Exodus\\exodus.wallet\\" wide
        $app06 = "\\Wallets\\Zcash\\" wide
        $app07 = "uCozMedia\\Uran" wide
        $app08 = "Comodo\\IceDragon" wide
        $app09 = "8pecxstudios\\Cyberfox" wide
        $app10 = "NETGATE Technologies\\BlackHaw" wide
        $app11 = "Moonchild Productions\\Pale Moon" wide
        
    condition:
        uint16(0)==0x5A4D and
        6 of ($str*) and all of ($dll*) and 10 of ($app*)
}
        