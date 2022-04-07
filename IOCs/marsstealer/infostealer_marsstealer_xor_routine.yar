rule infostealer_win_mars_stealer_xor_routine {
    meta:
        description = "Identifies samples of Mars Stealer based on the XOR deobfuscation routine."
        source = "SEKOIA.IO"
        reference = "https://blog.sekoia.io/mars-a-red-hot-information-stealer/"
        classification = "TLP:WHITE"
        hash = "4bcff4386ce8fadce358ef0dbe90f8d5aa7b4c7aec93fca2e605ca2cbc52218b"

    strings:
        $xor = {8b 4d ?? 03 4d ?? 0f be 19 8b 55 ?? 52 e8 ?? ?? ?? ?? 83 c4 ?? 8b c8 8b 45 ?? 33 d2 f7 f1 8b 45 ?? 0f be 0c 10 33 d9 8b 55 ?? 03 55 ?? 88 1a eb be}

    condition:
        uint16(0)==0x5A4D and $xor
}

