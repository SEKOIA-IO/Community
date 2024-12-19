rule rat_win_dcrat_qwqdanchun {
    meta:
        id = "8206a410-48b3-425f-9dcb-7a528673a37a"
        version = "1.0"
        description = "Find DcRAT samples (qwqdanchun) based on specific strings"
        author = "Sekoia.io"
        reference = "https://github.com/qwqdanchun/DcRat"
        creation_date = "2023-01-26"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "DcRatByqwqdanchun" wide
        $str02 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuXA==" wide
        $str03 = "Po_ng" wide
        $str04 = "Pac_ket" wide
        $str05 = "Perfor_mance" wide
        $str06 = "Install_ed" wide
        $str07 = "get_IsConnected" ascii
        $str08 = "get_ActivatePo_ng" ascii
        $str09 = "isVM_by_wim_temper" ascii
        $str10 = "save_Plugin" wide
        $str11 = "timeout 3 > NUL" wide
        $str12 = "ProcessHacker.exe" wide
        $str13 = "Select * from Win32_CacheMemory" wide
        
    condition:
        uint16(0) == 0x5A4D and 8 of them
}
        