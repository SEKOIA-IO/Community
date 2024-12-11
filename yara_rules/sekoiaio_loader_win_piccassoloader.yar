rule sekoiaio_loader_win_piccassoloader {
    meta:
        id = "91d9c2de-451e-467e-8f5c-38bbcce92b72"
        version = "1.0"
        description = "Detect the variant of Picasso used by GhostWriter as CVE-2023-38831 exploitation payload"
        source = "Sekoia.io"
        creation_date = "2023-09-07"
        classification = "TLP:CLEAR"
        
    strings:
        $ = {2c 27 44 65 63 72 79 70 74 6f 72 27 2c 27 6e 6f 64 65 27 2c 27 55 73 65 72 2d}
        $ = {5c 78 32 30 43 68 72 6f 6d 65 2f 31 30 27 2c 27 67 67 65 72 27 2c 27 73 65 64 43 69 70 68 65 72 27 2c 27 5f 61 70 70 65 6e 64 27 2c 27 5f 45 4e 43 5f 58 46 4f 52 4d 27 2c 27 57 53 63 72 69 70 74 2e 53 68 27}
        
    condition:
        1 of them
}
        