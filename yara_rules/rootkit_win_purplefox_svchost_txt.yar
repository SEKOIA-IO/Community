rule rootkit_win_purplefox_svchost_txt {
    meta:
        id = "e992d574-6a44-4bea-97e2-6d5579ce8d02"
        version = "1.0"
        description = "Detects Purple Fox payloads used during end-2021 and 2022 campaigns based on characteristics shared by TrendMicro details."
        author = "Sekoia.io"
        reference = "https://www.trendmicro.com/en_us/research/22/c/purple-fox-uses-new-arrival-vector-and-improves-malware-arsenal.html"
        creation_date = "2022-03-28"
        classification = "TLP:CLEAR"
        
    strings:
        $str0 = "C:\\ProgramData\\dll.dll,luohua" wide
        $str1 = "C:\\ProgramData\\7z.exe" wide
        $str2 = "F:\\hidden-master\\x64\\Debug\\QAssist.pdb" ascii
        $str3 = "F:\\Root\\sources\\MedaiUpdateV8\\Release\\MedaiUpdateV8.pdb" ascii
        $str4 = "cmd.exe /c RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255" ascii
        $str5 = "del /s /f %appdata%\\Mozilla\\Firefox\\Profiles\\*.db" ascii
        
    condition:
        4 of ($str*) and
        filesize > 7000KB and filesize <9500KB
}
        