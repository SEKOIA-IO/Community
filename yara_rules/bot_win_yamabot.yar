rule bot_win_yamabot {
    meta:
        id = "9f5b85c4-59e3-448f-b054-5b4932ee89bb"
        version = "1.0"
        description = "Detect the Yamabot implant used by Lazarus"
        author = "Sekoia.io"
        creation_date = "2023-08-29"
        classification = "TLP:CLEAR"
        hash1 = "1e4de822695570421eb2f12fdfe1d32ab8639655e12180a7ab3cf429e7811b8f"
        hash2 = "66415464a0795d0569efa5cb5664785f74ed0b92a593280d689f3a2ac68dca66"
        hash3 = "74529dd15d1953a47f0d7ecc2916b2b92865274a106e453a24943ca9ee434643"
        hash4 = "def2f01fbd4be85f48101e5ab7ddd82efb720e67daa6838f30fd8dcda1977563"
        
    strings:
        $s1 = "_/D_/Bot/YamaBot/"
        $s2 = "Go build ID: \"ujRRNborth3MgXzS7HTu/aYhLszO8_95srnr8Fk1n/Xr8P792kGZ_VUqOQVc97/kgx_H7YuMZBl2Ajyac2M\""
        
    condition:
        uint16be(0) == 0x4d5a and 1 of them and filesize > 3MB
}
        