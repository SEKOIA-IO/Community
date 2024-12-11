rule sekoiaio_infostealer_win_redline_strings {
    meta:
        version = "1.0"
        description = "Finds Redline samples based on characteristic strings"
        source = "Sekoia.io"
        creation_date = "2022-09-07"
        id = "0c9fcb0e-ce8f-44f4-90b2-abafcdd6c02e"
        classification = "TLP:CLEAR"
        
    strings:
        $gen01 = "ChromeGetRoamingName" ascii
        $gen02 = "ChromeGetLocalName" ascii
        $gen03 = "get_UserDomainName" ascii
        $gen04 = "get_encrypted_key" ascii
        $gen05 = "browserPaths" ascii
        $gen06 = "GetBrowsers" ascii
        $gen07 = "get_InstalledInputLanguages" ascii
        $gen08 = "BCRYPT_INIT_AUTH_MODE_INFO_VERSION" ascii
        
        $spe0 = "Profile_encrypted_value" wide
        $spe1 = "[AString-ZaString-z\\d]{2String4}\\.[String\\w-]{String6}\\.[\\wString-]{2String7}" wide
        $spe2 = "AFileSystemntivFileSystemirusPrFileSystemoduFileSystemct|AntiFileSystemSpyWFileSystemareProFileSystemduct|FireFileSystemwallProdFileSystemuct" wide
        $spe3 = "OpHandlerenVPHandlerN ConHandlernect%DSK_23%Opera GXcookies" wide
        $spe4 = "//settinString.Removeg[@name=\\PasswString.Removeord\\]/valuString.RemoveeROOT\\SecurityCenter" wide
        $spe5 = "ROOT\\SecurityCenter2Web DataSteamPath" wide
        $spe6 = "windows-1251, CommandLine:" wide
        $spe7 = "OFileInfopeFileInfora GFileInfoX StabFileInfole" wide
        $spe8 = "ApGenericpDaGenericta\\RGenericoamiGenericng\\" wide
        $spe9 = "*wallet*" wide
        
        $typ01 = "359A00EF6C789FD4C18644F56C5D3F97453FFF20" ascii
        $typ02 = "F413CEA9BAA458730567FE47F57CC3C94DDF63C0" ascii
        $typ03 = "A937C899247696B6565665BE3BD09607F49A2042" ascii
        $typ04 = "D67333042BFFC20116BF01BC556566EC76C6F7E2" ascii
        $typ05 = "4E3D7F188A5F5102BEC5B820632BBAEC26839E63" ascii
        $typ06 = "FB10FF1AD09FE8F5CA3A85B06BC96596AF83B350" ascii
        $typ07 = "77A9683FAF2EC9EC3DABC09D33C3BD04E8897D60" ascii
        $typ08 = "A8F9B62160DF085B926D5ED70E2B0F6C95A25280" ascii
        $typ09 = "718D1294A5C2D3F3D70E09F2F473155C4F567201" ascii
        $typ10 = "2FBDC611D3D91C142C969071EA8A7D3D10FF6301" ascii
        $typ11 = "2A19BFD7333718195216588A698752C517111B02" ascii
        $typ12 = "EB7EF1973CDC295B7B08FE6D82B9ECDAD1106AF2" ascii
        $typ13 = "04EC68A0FC7D9B6A255684F330C28A4DCAB91F13" ascii
        
    condition:
        uint16(0)==0x5A4D and (7 of ($gen*) or 3 of ($spe*) or 2 of ($typ*))
}
        