rule apt_mustangpanda_decrypt_payload {
    meta:
        id = "7b954007-0929-454d-8a10-05279a337f1b"
        version = "1.0"
        description = "Detects the decryption routine of DAT file"
        author = "Sekoia.io"
        creation_date = "2022-12-08"
        classification = "TLP:CLEAR"
        
    strings:
        $chunk_1 = {
        85 ??
        74 ??
        8B ??
        D1 EA
        A1 ?? ?? ?? ??
        03 C2
        A3 ?? ?? ?? ??
        30 04 29
        41
        3B ??
        72 EC
        }
        
    condition:
        filesize < 8MB and all of them
}
        