rule sekoiaio_trojan_win_bazarloader_setscreen {
    meta:
        id = "fe2709e5-5cdd-4e52-8ab4-79a56a60bef8"
        author = "Sekoia.io"
        creation_date = "2022-02-02"
        description = "Finds BazarLoader DLL using setscreen as exported entry. (I know this rule is bad but I wanted to experiment YARA rule writing on this specific dll exported entry setscreen)"
        version = "1.0"
        classification = "TLP:CLEAR"
        hash1 = "716f2ae73525362939d52104e809ea9da5e031f9d31f0b53d8de77df989c8b85"
        hash2 = "cf53b4386f5efb01cd84a8aa13f240b83ce152e8984233fa3ea440f01dcc0131"
        
    strings:
        $entry = {44 89 4c 24 ?? 4c 89 44 24 ?? (eb 1a|3a ff 74 0b)}
        $second = {48 89 54 24 ?? 48 89 4c 24 ?? (eb e9|66 3b e4 74 05) 48 83 c4 ?? c3}
        
    condition:
        $second in (@entry..@entry+50)
}
        