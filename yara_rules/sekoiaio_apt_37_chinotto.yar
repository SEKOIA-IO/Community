rule sekoiaio_apt_37_chinotto {
    meta:
        id = "eff8fd11-dc7a-4011-b083-181d0cca8790"
        version = "1.0"
        description = "Detects obfuscation and string of APT37 stealer"
        source = "Sekoia.io"
        creation_date = "2023-02-27"
        classification = "TLP:CLEAR"
        hash1 = "feab7940559392bbf38f29267509340569160e0a3b257fd86e5c65ae087ea014"
        hash2 = "c9d2c8b6011a53e68e4a6c6e51142cef3348951d0b379e49b1a65a1891538df5"
        hash3 = "2f5be3773e7e3a2f6806cdef154adfabc454c0e57a49e437c5889ce09b739302"
        hash4 = "5bf170c95ca0e2079653d694f783b5bcd38f274ea875f67f0b60db4ac552a66c"
        hash5 = "6fad04c836bc923f12ebaec8d8fb0c7091b044bf6f5c97e36d7bf46b8494f978"
        hash6 = "64fe964f342acca6d85d247c4f67503e4222a58dfc5c644dedc2006a4b356d39"
        hash7 = "6e216b265ea391f71f2a609df995f36b9ba8b17c8859f6d8e4ce4a076d351efd"
        hash8 = "70dcc03cde3dd5c5ec6a6a240190cfb51667aaba9c867e20281e8dfc43afa891"
        hash9 = "5053390bde150b771f8efe344b692c6c5718ba9203a4b23f5323af1ee9060ff2"
        hash10 = "089e4dfd8b25afe596eff05baae86156a4e3243c84faa15416cff31a5120e107"
        hash11 = "37e096338a78cb06d6236cb5a04cf125f191871ded3c9421f08a37890a095eb8"
        hash12 = "b90a2b0249407b271a5d849fe82cbf4e9a31c2c6259caf515c9be3897e327414"
        hash13 = "8f4751ed22619b04009c4b85ec45c8140b570835ca4c638c9e6019e7b7eb66c7"
        
    strings:
        $chunk_1 = {
        C7 85 ?? ?? ?? ?? ?? ?? ?? 00
        C7 85 ?? ?? ?? ?? ?? ?? ?? 00
        33 C0
        EB 03
        8D 49 00
        8B 8C 85 ?? ?? ?? ??
        3B 8C 85 ?? ?? ?? ??
        }
        
        $chunk_2 = {
        C7 84 24 ?? ?? ?? ?? ?? ?? 0? 00
        C7 84 24 ?? ?? ?? ?? ?? ?? 0? 00
        33 C0
        EB 0D
        8D A4 24 00 00 00 00
        8D 9B 00 00 00 00
        8B 8C 84 ?? ?? ?? ??
        3B 8C 84 ?? ?? ?? ??
        }
        
        $movs_zip_dir_start = { C7 45 ?? 5A 69 70 20 C7 45 ?? 44 69 72 20 C7 45 ?? 53 74 61 72  C7 45 ?? 74 20 2D 20}
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and
        filesize < 1MB and ($chunk_1 or $chunk_2) and $movs_zip_dir_start
}
        