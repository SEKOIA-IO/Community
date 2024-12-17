rule sekoiaio_stealer_win_strela {
    meta:
        id = "2c98f84a-4329-476b-98b8-d8e2387b1b69"
        version = "1.0"
        description = "Detects IOCs related to the Strela stealer"
        author = "Sekoia.io"
        creation_date = "2024-04-09"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "SOFTWARE\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676\\" ascii fullword
        $s2 = "%s%s\\logins.json" ascii fullword
        $s3 = "%s%s\\key4.db" ascii fullword
        $s4 = "\\Thunderbird\\Profiles\\" ascii fullword
        $s5 = "/server.php" ascii fullword
        $s6 = "out.dll" ascii fullword
        
    condition:
        all of them
}
        