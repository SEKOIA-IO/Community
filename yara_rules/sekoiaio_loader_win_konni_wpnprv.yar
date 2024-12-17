rule sekoiaio_loader_win_konni_wpnprv {
    meta:
        id = "02162533-4ace-42bf-8df0-38b140487f01"
        version = "1.0"
        description = "Detect the wpnprv DLLs used for KONNI for UAC bypass"
        author = "Sekoia.io"
        creation_date = "2023-09-26"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "wpnprv.dll"
        // Name of the malicious export
        $ = "IIIIIIII" fullword
        $ = "wusa.exe" wide
        $ = "winver.exe" wide
        $ = "MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" wide
        $ = "taskmgr.exe" wide
        
    condition:
        uint16(0)==0x5A4D and all of them
}
        