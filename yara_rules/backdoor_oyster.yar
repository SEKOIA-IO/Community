rule backdoor_oyster {
    meta:
        id = "f95f98ea-1e52-45ae-8abf-a986f95d4ab2"
        version = "1.0"
        description = "Detects files related to the Oyster backdoor."
        author = "Sekoia.io"
        creation_date = "2024-08-29"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "CleanUp30.dll" ascii fullword
        $s2 = "MSTeamsSetup_c_l_.exe" ascii fullword
        
    condition:
        all of them
}
        