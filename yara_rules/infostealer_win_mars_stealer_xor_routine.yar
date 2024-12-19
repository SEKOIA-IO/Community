rule infostealer_win_mars_stealer_xor_routine {
    meta:
        id = "3e2c7440b2fc9e4b039e6fa8152ac8ff"
        version = "1.0"
        description = "Detect Mars Stealer based on a specific XOR routine"
        author = "Sekoia.io"
        creation_date = "2022-04-06"
        classification = "TLP:CLEAR"
        
    strings:
        $xor = {8b 4d ?? 03 4d ?? 0f be 19 8b 55 ?? 52 e8 ?? ?? ?? ?? 83 c4 ?? 8b c8 8b 45 ?? 33 d2 f7 f1 8b 45 ?? 0f be 0c 10 33 d9 8b 55 ?? 03 55 ?? 88 1a eb be}
        
    condition:
        uint16(0)==0x5A4D and $xor
}
        