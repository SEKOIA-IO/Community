rule sekoiaio_apt_mustangpanda_windows_shellcode_decryptionalgorithm {
    meta:
        id = "c9873a5f-97a6-477f-a1a0-650441c73444"
        version = "1.0"
        description = "Decryption routine for Shellcode of MustangPanda"
        author = "Sekoia.io"
        creation_date = "2022-12-05"
        classification = "TLP:CLEAR"
        
    strings:
        $chunk_1 = {
        7E ??
        8B 55 ??
        53
        56
        8B 75 ??
        57
        8B 7D ??
        4F
        8D A4 24 ?? ?? ?? ??
        8A 1C 11
        30 1C 30
        }
        
    condition:
        
        filesize < 8MB and all of them
}
        