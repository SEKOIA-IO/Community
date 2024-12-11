rule sekoiaio_infostealer_win_edgeguard {
    meta:
        id = "bbdb362f-d235-48f8-8fa5-d340d4e3e3f0"
        version = "1.0"
        description = "Finds EdgeGuard Stealer samples based on specific strings"
        source = "Sekoia.io"
        creation_date = "2023-08-22"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "main.downloadnecessary" ascii
        $str02 = "main.extractchromepasswords" ascii
        $str03 = "main.extracttasksch" ascii
        $str04 = "main.BrowserDownloadsViewExtract" ascii
        $str05 = "main.stealmetamask" ascii
        $str06 = "main.stealexoduswallet" ascii
        $str07 = "main.moveatomic" ascii
        $str08 = "main.movefirefoxcookies" ascii
        $str09 = "main.movepasswords" ascii
        $str10 = "main.FinallyZIPIPFolder" ascii
        $str11 = "edgeguard.business" ascii
        $str12 = "/License.XenArmor" ascii
        $str13 = "/TaskSchedulerView.exe" ascii
        $str14 = "/BrowsingHistoryView.exe" ascii
        $str15 = "/outlookfiles/starter.exe" ascii
        $str16 = "/outlookfiles/External.zip" ascii
        $str17 = "/outlookfiles/XenManager.dll" ascii
        $str18 = "/outlookfiles/EmailPasswordRecoveryPro.exe" ascii
        
    condition:
        uint16(0) == 0x5a4d and 10 of ($str*)
}
        