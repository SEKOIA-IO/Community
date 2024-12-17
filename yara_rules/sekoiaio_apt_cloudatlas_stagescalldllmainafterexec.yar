rule sekoiaio_apt_cloudatlas_stagescalldllmainafterexec {
    meta:
        id = "a24b7887-87f6-44e3-80c5-cd117e694595"
        version = "1.0"
        description = "Detects call to dllmain after execution of exported function"
        author = "Sekoia.io"
        creation_date = "2023-10-31"
        classification = "TLP:CLEAR"
        
    strings:
        $chunk_1 = {
        55
        8B EC
        83 EC 10
        C7 45 ?? 00 00 00 00
        83 7D ?? 00
        74 ??
        8B 45 ??
        89 45 ??
        8B 4D ??
        8B 51 ??
        03 55 ??
        89 55 ??
        8B 45 ??
        8B 48 ??
        03 4D ??
        89 4D ??
        6A 00
        6A 00
        FF 75 ??
        FF 55 ??
        68 00 80 00 00
        6A 00
        8B 55 ??
        52
        FF 15 ?? ?? ?? ??
        C7 45 ?? 01 00 00 00
        8B 45 ??
        8B E5
        5D
        C2 04 00
        }
        
    condition:
        any of them
}
        