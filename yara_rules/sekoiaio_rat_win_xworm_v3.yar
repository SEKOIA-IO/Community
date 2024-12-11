rule sekoiaio_rat_win_xworm_v3 {
    meta:
        version = "1.0"
        description = "Finds XWorm (version XClient, v3) samples based on characteristic strings"
        source = "Sekoia.io"
        creation_date = "2023-03-03"
        id = "5fb1cbd3-1e37-43b9-9606-86d896f2150b"
        classification = "TLP:CLEAR"
        hash = "0016647c3c7031e744c0af6f9eadb73ab5cab1ca4f8ce7633f4aa069b62755cd"
        hash = "07e747a9313732d2dcf7609b6a09ac58d38f5643299440b827ec55f260e33c12"
        hash = "de0127ba872c0677c3594c66b2298edea58d097b5fa697302a16b1689147b147"
        
    strings:
        $str01 = "$VB$Local_Port" ascii
        $str02 = "$VB$Local_Host" ascii
        $str03 = "get_Jpeg" ascii
        $str04 = "get_ServicePack" ascii
        $str05 = "Select * from AntivirusProduct" wide
        $str06 = "PCRestart" wide
        $str07 = "shutdown.exe /f /r /t 0" wide
        $str08 = "StopReport" wide
        $str09 = "StopDDos" wide
        $str10 = "sendPlugin" wide
        $str11 = "OfflineKeylogger Not Enabled" wide
        $str12 = "-ExecutionPolicy Bypass -File \"" wide
        $str13 = "Content-length: 5235" wide
        
    condition:
        uint16(0)==0x5A4D and 8 of them
}
        