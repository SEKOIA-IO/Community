rule sekoiaio_guloader_lnk_file {
    meta:
        id = "ecc07753-0910-445b-bf84-911b17195894"
        version = "1.0"
        description = "LNK file delivering Guloader"
        source = "Sekoia.io"
        creation_date = "2024-02-07"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "$PSHOME" wide
        $s2= "&(${" wide
        $s3 = "}::ToString(" wide
        $s4 = "$([TYPE]${" wide
        
    condition:
        uint32be(0) == 0x4c000000 and all of them
}
        