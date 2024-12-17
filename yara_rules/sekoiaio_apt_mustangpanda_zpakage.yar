rule sekoiaio_apt_mustangpanda_zpakage {
    meta:
        id = "a4767d12-5058-4a26-be62-0cec685917bd"
        version = "1.0"
        description = "Detect obfuscation seen in ZPAKAGE"
        author = "Sekoia.io"
        creation_date = "2023-03-27"
        classification = "TLP:CLEAR"
        hash = "711c0e83f4e626a7b54e3948b281a71915a056c5341c8f509ecba535bc199bee"
        
    strings:
        $chunk_1 = {
        88 94 1D ?? ?? ?? ??
        8A 84 1D ?? ?? ?? ??
        83 ?? ??
        88 84 1D ?? ?? ?? ??
        8A 84 1D ?? ?? ?? ??
        83 ?? ??
        88 84 1D ?? ?? ?? ??
        8A 84 1D ?? ?? ?? ??
        83 ?? ??
        88 84 1D ?? ?? ?? ??
        0F BE 8C 1D ?? ?? ?? ??
        0F BE 84 1D ?? ?? ?? ??
        }
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 1MB and filesize < 11MB and
        #chunk_1 > 20
}
        