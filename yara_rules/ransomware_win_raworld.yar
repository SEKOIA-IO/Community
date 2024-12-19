rule ransomware_win_raworld {
    meta:
        id = "a9ed9c5a-7a0e-4c2e-90f4-d52f5589b2b8"
        version = "1.0"
        description = "Detects files related to stage 1 of a campaign from the ransomware group RA World."
        author = "Sekoia.io"
        creation_date = "2024-07-24"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "Loder.exe" ascii fullword
        $s2 = "Stage2.exe" wide
        $s3 = "SYSVOL" wide
        $s4 = "Finish.exe" wide
        $s5 = "Exclude.exe" wide
        $s6 = "Stage3.exe" wide
        $s7 = "Pay.txt" ascii fullword
        $s8 = "RA World" ascii fullword
        $s9 = "Stage1.exe" ascii fullword
        
    condition:
        4 of them
}
        