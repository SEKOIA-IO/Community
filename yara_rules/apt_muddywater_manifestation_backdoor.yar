rule apt_muddywater_manifestation_backdoor {
    meta:
        id = "998fb0ab-73ed-41e5-b87e-f987b8f05a8c"
        version = "1.0"
        description = "Detects Muddys manifestation JScript backdoor"
        author = "Sekoia.io"
        creation_date = "2022-01-13"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "/^\\s+|\\s+$/g" ascii
        $l2 = "while (1) {"  ascii
        $l3 = { 57 53 63 72 69 70 74 2e 73 6c 65 65 70 28 ?? ?? 20 2a 20 31 30 30 30 29 3b }
        $s4 = ")+ key , false)" ascii
        $s5 = ")+ data , false)" ascii
        
    condition:
        filesize > 1000 and
        ($l3 in (@l2..@l2+300)) and (any of ($s*))
}
        