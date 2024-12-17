rule sekoiaio_downloader_win_cobianrat {
    meta:
        id = "7a86c17f-bf4e-4465-9488-244b75fc36f1"
        version = "1.0"
        description = "Detect CobianRAT downloader"
        author = "Sekoia.io"
        creation_date = "2024-08-23"
        classification = "TLP:CLEAR"
        hash = "7a70779d9d7de5e370fac0fa2d4ccd13"
        hash = "2ce40599a4990680db3af5defcd5381a"
        hash = "56515c48f82475e7bb6a26b027a459d7"
        hash = "3450bece12bd8103d5e718a2661d0404"
        hash = "132858739129d2b863dc547facbed7e9"
        hash = "693bd96d162c54d7e9605580eaf54a6e"
        hash = "d03a4988e22e6c7b2a03efa2bdb1502d"
        hash = "ab8c68b907ec2ce316bf18f00938710c"
        
    strings:
        $ = {24 00 44 00 6F 00 77 00 6E 00 6C 00 6F 00 61 00 64 00 55 00 72 00 6C 00 20 00 3D 00 20 00 27}
        
    condition:
        uint16be(0) == 0x4d5a and all of them
}
        