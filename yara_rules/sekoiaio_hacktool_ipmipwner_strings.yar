rule sekoiaio_hacktool_ipmipwner_strings {
    meta:
        id = "2ac736b5-33bb-477f-a98c-57cc2744d251"
        version = "1.0"
        description = "Detects ipmiPwner script"
        source = "Sekoia.io"
        creation_date = "2023-12-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "{status} Using the list of users that the {lgcyan}script"
        $ = "--host 192.168.1.12 -p 624 -uW /opt/SecLists/Usernames/"
        
    condition:
        all of them and filesize < 10KB
}
        