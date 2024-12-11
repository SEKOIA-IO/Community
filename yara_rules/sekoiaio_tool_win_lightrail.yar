rule sekoiaio_tool_win_lightrail {
    meta:
        id = "39259f2c-11fe-4edd-8a9e-f36920132272"
        version = "1.0"
        description = "Detect the LIGHTRAIL tunneler used by UNC1549"
        source = "Sekoia.io"
        creation_date = "2024-02-29"
        classification = "TLP:CLEAR"
        reference = "https://www.mandiant.com/resources/blog/suspected-iranian-unc1549-targets-israel-middle-east"
        hash1 = "e7ddab967b0487827db069833221aa2fe4ca05f7cda976cbc528ecb306a22774"
        hash2 = "4ecd511d9654f7fd66a61eb4ab6d7153040b5092d1594ff39935f01fbdbd4914"
        hash3 = "3472bc8ed6182eb17811c97ada7ebd48034ad09b6a7062b341fe09818d7a309f"
        hash4 = "ec7b97092278123f0c0613c5f9252eeccf55265d4aa5f2cfed57a63ebf3530ac"
        hash5 = "8f3757b8f5888a1303af71cbc1a106927d3d6c45552ee192c3ed0347804c2194"
        hash6 = "8b47b5ed1ed7afcc9194e1350d4e1996bd91ca3204747b586f309f4609a1a4cc"
        
    strings:
        $s1 = "lastenzug.dll"
        $s2 = "Lastenzug.dll"
        $azure = ".cloudapp.azure.com" wide
        
    condition:
        uint16be(0)==0x4d5a and 1 of ($s*) and $azure
}
        