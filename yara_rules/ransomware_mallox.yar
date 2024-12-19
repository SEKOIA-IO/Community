rule ransomware_mallox {
    meta:
        id = "7e2edc94-26e4-4024-8bc0-8e90d76f5a96"
        version = "1.0"
        description = "Rule to detect mallox ransomware samples."
        author = "Sekoia.io"
        creation_date = "2023-02-20"
        modification_date = "2023-05-24"
        classification = "TLP:CLEAR"
        hash1 = "2a549489e2455a2d84295604e29c727dd20d65f5a874209840ce187c35d9a439"
        hash2 = "3f843cbffeba010445dae2b171caaa99c6b56360de5407da71210d007fe26673"
        hash3 = "4075d6e02c022ee45e0cd1c826abf749200639ee8ebc42375dac2430abafb5d6"
        hash4 = "4db69a0643f6ec795e5450a0563605e91293f233aa60715ae09ed8effa3b7267"
        hash5 = "77fdce66e7f909300e4493cbe7055254f7992ba65f9b7445a6755d0dbd9f80a5"
        hash6 = "8e974a3be94b7748f7971f278160a74d738d5cab2c3088b1492cfbbd05e83e22"
        hash7 = "a5085e571857ec54cf9625050dfc29a195dad4d52bea9b69d3f22e33ed636525"
        hash8 = "df64e87ecb30f4cadf54f2c1b3d3cba8cc2d315db0fd4af2d11add57baa56f6a"
        hash9 = "e7e00e0f817fcb305f82aec2e60045fcdb1b334b2621c09133b6b81284002009"
        
    strings:
        $s1 = "C:\\HOW TO RECOVER !!.TXT" wide ascii nocase
        $s2 = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\Raccine" wide ascii nocase
        $s3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\vssadmin.exe" wide ascii nocase
        $s4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wmic.exe" wide ascii nocase
        $s5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wbadmin.exe" wide ascii nocase
        $s6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\bcdedit.exe" wide ascii nocase
        $s7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\powershell.exe" wide ascii nocase
        $s8 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\diskshadow.exe" wide ascii nocase
        $s9 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\net.exe" wide ascii nocase
        $s10 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskkill.exe" wide ascii nocase
        $s11 = "bcdedit /set {current} recoveryenabled no" wide ascii nocase
        $mallox_fargo = ".FARGO" wide ascii nocase
        $mallox_mallox = ".mallox" wide ascii nocase
        $mallox_exploit = "newexploit@tutanota.com"
        
    condition:
        uint16be(0) == 0x4d5a and all of ($s*) and 1 of ($mallox_*)
}
        