rule sekoiaio_trojan_win_bbtok_iso_sep23 {
    meta:
        id = "6032853d-b872-4b2e-913d-366e7f3d0f32"
        version = "1.0"
        description = "Finds BBTok installation ISO file"
        source = "Sekoia.io"
        reference = "https://research.checkpoint.com/2023/behind-the-scenes-of-bbtok-analyzing-a-bankers-server-side-components/"
        creation_date = "2023-09-26"
        classification = "TLP:CLEAR"
        hash = "140e83d2e0d012cdd5625ea89c3b3af05a80877cfc8215bbe20823e7e88c80b1"
        
    strings:
        $iso = {43 44 30 30 31} //iso magic number
        
        $str01 = "POWERISO" ascii
        $str02 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" ascii wide
        $str03 = ".pdf /Y & start" wide
        $str04 = "\\MSBuild.exe -nologo \\\\" ascii wide
        
    condition:
        all of them and filesize < 500KB
}
        