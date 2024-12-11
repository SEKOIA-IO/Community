rule sekoiaio_apt_cloudatlas_init_module_virtualalloc {
    meta:
        id = "299ed681-9d1f-4b47-8389-ff5a608f49d4"
        version = "1.0"
        description = "Find init module of CloudAtlas with params passed to VirtualAlloc"
        source = "Sekoia.io"
        creation_date = "2023-09-19"
        classification = "TLP:CLEAR"
        hash1 = "02a1a9582f5ccf421b08c41c35049416b9cdefc9228daf6b38d95e9b0930cc5a"
        hash2 = "c7f19c7c295c86867ea7fa4597ba0cebe12f751753866e7298fd5d84676facc3"
        
    strings:
        $chunk_1 = {
        6A 40
        68 00 30 10 00
        8B 8D ?? ?? ?? ??
        8B 51 50
        52
        6A 00
        FF 15 ?? ?? ?? ??
        }
        
    condition:
        (uint32be(0) == 0x7f454c46 or uint16be(0) == 0x4d5a) and $chunk_1 and filesize < 3MB
}
        