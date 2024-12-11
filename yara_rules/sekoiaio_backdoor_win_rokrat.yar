rule sekoiaio_backdoor_win_rokrat {
    meta:
        id = "97a3acc1-4120-4d67-a6ad-fa204f2fd7f5"
        version = "1.0"
        description = "Detect the RokRAT malware"
        source = "Sekoia.io"
        creation_date = "2023-07-11"
        classification = "TLP:CLEAR"
        hash1 = "84760cac26513915ebfb0a80ad3ddabe62f03ec4fda227d63e764f9c4a118c4e"
        hash2 = "758348521331bb18241d1cfc90d7e687dbc5bad8d596a2b2d6a9deb6cfc8cb1d"
        hash3 = "2a253c2aa1db3f809c86f410e4bd21f680b7235d951567f24d614d8e4d041576"
        hash4 = "ebce34cdeb20bc8c75249ce87a3080054f48b03ef66572fbc9dc40e6c36310d6"
        hash5 = "a1e4e95a20120f16adacb342672eec1e73bd7826b332096f046bb7e2b7cd80a1"
        hash6 = "3be58a7a7a25dbceee9e7ef06ef20aa86aef083be19db9e5ffb181d3f9f6615a"
        hash7 = "fa4df84071b9ae20b321e4d22162d8480f6992206bc046e403c2fbedd1655503"
        hash8 = "aa76b4db29cf929b4b22457ccb8cd77308191f091cde2f69e578ade9708d7949"
        
    strings:
        // String in all samples since 2019
        $ = "--wwjaughalvncjwiajs--"
        
        // {"path":"%s","mode":{".tag":"overwrite"}}
        $ = {7b 00 22 00 70 00 61 00 74 00 68 00 22 00 3a 00 22 00 25 00 73 00 22 00 2c 00 22 00 6d 00 6f 00 64 00 65 00 22 00 3a 00 7b 00 22 00 2e 00 74 00 61 00 67 00 22 00 3a 00 22 00 6f 00 76 00 65 00 72 00 77 00 72 00 69 00 74 00 65 00 22 00 7d 00 7d}
        
        // https://cloud-api.yandex.net/v1/disk/resources/upload?path=%s&overwrite=%s
        $ = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 6c 00 6f 00 75 00 64 00 2d 00 61 00 70 00 69 00 2e 00 79 00 61 00 6e 00 64 00 65 00 78 00 2e 00 6e 00 65 00 74 00 2f 00 76 00 31 00 2f 00 64 00 69 00 73 00 6b 00 2f 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 3f 00 70 00 61 00 74 00 68 00 3d 00 25 00 73 00 26 00 6f 00 76 00 65 00 72 00 77 00 72 00 69 00 74 00 65 00 3d 00 25 00 73}
        
    condition:
        uint16(0)==0x5A4D
        and any of them
}
        