rule storm_1811_files_dat {
    meta:
        id = "8b14f276-0c39-422b-9b19-d96b139a7ae8"
        version = "1.0"
        description = "Detects files used in a campaign performed by the intrusion set Storm-1811"
        author = "Sekoia.io"
        creation_date = "2024-06-10"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "RuntimeBroker" ascii fullword
        $s2 = "InstallSpamFilters" ascii fullword
        $s3 = "newfile333.txt" ascii fullword
        $s4 = "Installing spam filter kb_outlook" ascii fullword
        $s5 = "s.zip" ascii fullword
        $s6 = "Update completed" ascii fullword
        $s7 = "Updates installed" ascii fullword
        $s8 = "update_log.tgz uploaded ok" ascii fullword
        $s9 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii fullword
        $s10 = "runtimebroker_connect" ascii fullword
        
    condition:
        5 of them
}
        