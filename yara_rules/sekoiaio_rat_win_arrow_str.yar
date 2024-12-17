rule sekoiaio_rat_win_arrow_str {
    meta:
        version = "1.0"
        description = "Finds Arrow RAT samples based on the specific malware strings"
        author = "Sekoia.io"
        creation_date = "2022-08-19"
        id = "69f6572c-91ed-4fb6-b886-5ad2dabef3d3"
        classification = "TLP:CLEAR"
        
    strings:
        $hvnc01 = "DESKTOP_JOURNALRECORD" ascii
        $hvnc02 = "DESKTOP_ENUMERATE" ascii
        $hvnc03 = "DESKTOP_SWITCHDESKTOP" ascii
        $hvnc04 = "DESKTOP_CREATEWINDOW" ascii
        $hvnc05 = "StartHVNC" ascii
        
        $str01 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3MgTlRcQ3VycmVudFZlcnNpb25cV2lubG9nb25c" wide //Software\Microsoft\Windows NT\CurrentVersion\Winlogon\
        $str02 = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -Command Add-MpPreference -ExclusionPath" wide
        $str03 = "cvtres.exe" wide
        $str04 = "qbkTHriRRbQjaArtJfF" wide
        $str05 = "29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3MgTlRcQ3VycmVudFZlcnNpb25cV2lubG9nb24=" wide
        $str06 = "Stub.exe" ascii wide
        $str07 = "DePikoloData" ascii
        
    condition:
        uint16be(0) == 0x4d5a and 4 of ($hvnc*) and 5 of ($str*)
}
        