rule tool_win_sharpshares {
    meta:
        id = "ef90d573-12f8-4216-9a9e-96e7d1e841d0"
        version = "1.0"
        description = "Finds sharpshares EXE based on strings"
        author = "Sekoia.io"
        reference = "https://github.com/mitchmoser/SharpShares/releases"
        creation_date = "2024-06-10"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "<GetAllShares>b__0" ascii
        $str02 = "<SearchLDAP>b__0_0" ascii
        $str03 = "get_AccessControlType" ascii
        $str04 = "get_IdentityReference" ascii
        $str05 = "get_PropertiesToLoad" ascii
        $str06 = "SharpShares\\obj\\Release\\SharpShares.pdb" ascii
        $str07 = "/filter:SYSVOL,NETLOGON,IPC$,PRINT$" wide
        $str08 = "/threads:50 /ldap:servers" wide
        $str09 = "SharpShares.exe" ascii wide
        $str10 = "[+] LDAP Search Results:" wide
        $str11 = "[+] Finished Enumerating Shares" wide
        
    condition:
        uint16(0)==0x5A4D and 6 of them
}
        