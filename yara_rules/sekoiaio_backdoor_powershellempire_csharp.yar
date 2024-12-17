rule sekoiaio_backdoor_powershellempire_csharp {
    meta:
        id = "952e8e9b-8e4d-4550-9cf4-7ffd2f9d0672"
        version = "1.0"
        description = "Detects CSharp version of Empire"
        author = "Sekoia.io"
        creation_date = "2022-04-15"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "[-] Catastrophic .Net Agent Failure, Attempting Agent Restart:" ascii wide
        $ = "[!] Upload failed - No Delimiter"  ascii wide
        $ = "SELECT * FROM Win32_IP4RouteTable" ascii wide
        $ = "no shell command supplied" ascii wide
        $ = "[-] CmdletInvocationException:" ascii wide
        $ = "[*] File download of" ascii wide
        $ = "Script successfully saved in memory" ascii wide
        $ = "Invoke-Empire" ascii wide
        $ = "website to reach:" ascii wide
        
    condition:
        uint16be(0) == 0x4d5a and 5 of them  and filesize < 1MB
}
        