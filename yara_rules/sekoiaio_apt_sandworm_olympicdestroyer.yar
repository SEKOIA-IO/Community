rule sekoiaio_apt_sandworm_olympicdestroyer {
    meta:
        id = "6820eb32-fea2-4a00-a5a2-672ba09f8206"
        version = "1.0"
        description = "Detects OlympicDestroyer malware"
        author = "Sekoia.io"
        creation_date = "2022-04-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "cmd.exe /c (ping 0.0.0.0 > nul)" wide
        $ = "if exist %programdata%\\evtchk.txt" wide
        $ = "\\\\.\\pipe\\%ls" wide
        $ = "%ProgramData%\\%COMPUTERNAME%.exe" wide
        $ = "(exit 5) else ( type nul >" wide
        $ = "Select * From Win32_ProcessStopTrace" nocase
        
    condition:
        uint16be(0) == 0x4d5a and
        3 of them
}
        