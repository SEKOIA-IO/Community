rule sekoiaio_hacktool_mimikatz_obfuscated {
    meta:
        id = "bac4bb61-d250-4fc3-95a5-edd4e3c7ff83"
        version = "1.0"
        description = "Detects Mimikatz on strings obfuscation"
        author = "Sekoia.io"
        creation_date = "2022-07-22"
        classification = "TLP:CLEAR"
        
    strings:
        $xor1 = "Benjamin Delpy" xor
        $xor2 = "sekurlsa" xor wide
        $xor3 = "minidumpfile.dmp" wide
        $xor4 = "lsadump_dcsync"  xor wide
        $xor5 = "kuhl_m_lsadump_getSamKey" xor wide
        
        $b1 = "Benjamin Delpy" base64
        $b2 = "sekurlsa" base64 wide
        $b3 = "minidumpfile.dmp" base64 wide
        $b4 = "lsadump_dcsync" base64 wide
        $b5 = "kuhl_m_lsadump_getSamKey" base64 wide
        
    condition:
        uint16be(0) == 0x4d5a and 3 of them and filesize < 5MB
}
        