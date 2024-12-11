rule sekoiaio_trojan_win_bbtok_dll1_sep23 {
    meta:
        id = "eebed24b-24ec-4a85-852c-52d0acc9a698"
        version = "1.0"
        description = "Finds BBTok installation DLL file"
        source = "Sekoia.io"
        reference = "https://research.checkpoint.com/2023/behind-the-scenes-of-bbtok-analyzing-a-bankers-server-side-components/"
        creation_date = "2023-09-26"
        classification = "TLP:CLEAR"
        hash = "5353956345206982af9bde55300fc405ba6e40722e8f51e8717c30ad32bc8f91"
        
    strings:
        $str01 = "C:\\Windows\\System32\\rundll32.exe" wide
        $str02 = "C:\\ProgramData\\mmd.exe" wide
        $str03 = "REG ADD HKCU\\Software\\Classes\\.pwn\\Shell\\Open\\command -ve /d" wide
        $str04 = "C:\\ProgramData\\mmd.exe \\\\" wide
        $str05 = "\\file\\Trammy.dll" wide
        $str06 = "Dacl & REG DELETE HKCU\\Software\\Classes\\ms-settings /f" wide
        $str07 = "REG DELETE  HKCU\\Software\\Classes\\.pwn /f" wide
        $str08 = "REG ADD HKCU\\Software\\Classes\\ms-settings\\CurVer -ve /d \".pwn\" /f" wide
        $str09 = "timeout /t 3 >nul & start /MIN computerdefaults.exe" wide
        $str10 = "set_StartInfo" ascii
        $str11 = "set_WindowStyle" ascii
        
    condition:
        uint16(0)==0x5a4d and 7 of them
        and filesize < 50KB
}
        