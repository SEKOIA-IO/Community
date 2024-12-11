rule sekoiaio_storm_1811_screenconnect_update {
    meta:
        id = "252ef24a-14dc-41e8-ba91-dcb9b6deb428"
        version = "1.0"
        description = "Detects files used in a campaign performed by the intrusion set Storm-1811"
        source = "Sekoia.io"
        creation_date = "2024-06-11"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "upd100.appspot.com/update/u.zip" ascii fullword
        $s2 = "Unzip ok" ascii fullword
        $s3 = "Installing update" ascii fullword
        $s4 = "Administrators" ascii fullword
        $s5 = "I am not admin" ascii fullword
        $s6 = "I am admin" ascii fullword
        $s7 = "ScreenConnect.ClientSetup.exe" ascii fullword
        $s8 = "for %%x in (%IPS%) do (" ascii fullword
        
    condition:
        6 of them
}
        