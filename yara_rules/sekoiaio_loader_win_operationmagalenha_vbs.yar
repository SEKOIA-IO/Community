rule sekoiaio_loader_win_operationmagalenha_vbs {
    meta:
        version = "1.0"
        description = "Finds VBS file loading the PeepingTitle backdoor"
        source = "Sekoia.io"
        reference = "https://www.sentinelone.com/labs/operation-magalenha-long-running-campaign-pursues-portuguese-credentials-and-pii/"
        creation_date = "2023-05-31"
        id = "b1f705d1-de3e-4ce6-9bb7-0e39b6e79add"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "'Skip to content" ascii
        $str02 = "'Search" ascii
        $str03 = "'Sign in" ascii
        $str04 = "'Sign up" ascii
        $str05 = "'Code" ascii
        $str06 = "'Terms" ascii
        $str07 = "'Privacy" ascii
        $str08 = "'Security" ascii
        $str09 = "'Status" ascii
        $str10 = "'Docs" ascii
        $str11 = "'Contact GitHub" ascii
        $str12 = "'Pricing" ascii
        $str13 = "'API" ascii
        $str14 = "'Training" ascii
        $str15 = "'Blog" ascii
        $str16 = "'About" ascii
        
        $vbs01 = "WScript.Sleep" ascii nocase
        $vbs02 = "Set obj" ascii nocase
        $vbs03 = "Dim obj" ascii nocase
        $vbs04 = "https://tinyurl.com" ascii nocase
        $vbs05 = "C:\\Users\\Public" ascii nocase
        $vbs06 = "CreateObject(\"WScript.Shell\")" ascii nocase
        $vbs07 = ".SaveToFile" ascii nocase
        
    condition:
        10 of ($str*) and 5 of ($vbs*)
}
        