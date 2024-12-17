rule sekoiaio_trojan_win_bbtok_lnk_sep23 {
    meta:
        id = "b1d5dae6-d92f-4a4a-ae90-528cdb3e9e4c"
        version = "1.0"
        description = "Finds BBTok installation LNK file"
        author = "Sekoia.io"
        reference = "https://research.checkpoint.com/2023/behind-the-scenes-of-bbtok-analyzing-a-bankers-server-side-components/"
        creation_date = "2023-09-26"
        classification = "TLP:CLEAR"
        hash = "32bf07e3740399105359b62d8a612dfa731b024e06c9104b71b496919b5efe9e"
        
    strings:
        $lnk = {4C 00 00 00} //lnk magic number
        
        $str01 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" ascii wide
        $str02 = ".pdf /Y & start" wide
        $str03 = "\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe -nologo" wide
        
    condition:
        all of them and filesize < 10KB
}
        