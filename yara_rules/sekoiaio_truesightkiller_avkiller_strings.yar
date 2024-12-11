rule sekoiaio_truesightkiller_avkiller_strings {
    meta:
        id = "8f249ac4-5181-4169-9eb2-7d73ec4fd68d"
        version = "1.0"
        description = "TrueSightKiller based on string"
        source = "Sekoia.io"
        creation_date = "2024-10-29"
        classification = "TLP:CLEAR"
        hash = "891202963430a4b1dea2dc5b9af01dc5"
        hash = "367af202029bf51fc347a8f414fa2a5c"
        hash = "64439836d69084b129c2dc4264176149"
        hash = "6e69b890b1c228fa4225776b185b5af7"
        hash = "daaf7bdf1e7fd882c0bfb89450ec0ab2"
        hash = "dcf36765ed9386c169eb2695d26f6a6f"
        
    strings:
        $ = "[+] Process PID: " wide
        $ = "[-] OpenSCManager failed" wide
        $ = "[+] Creating service: truesight" wide
        $ = "[+] Full path: " wide
        $ = "[-] Error getting current directory." wide
        $ = "[-] CreateService failed" wide
        $ = "[!] Service is already running" wide
        $ = "[-] QueryServiceStatus failed" wide
        $ = "[-] StartService failed" wide
        $ = "[+] Driver loaded successfully!" wide
        $ = "[-] OpenService failed" wide
        $ = "[-] ControlService failed" wide
        $ = "[-] DeleteService failed" wide
        $ = "Welcome to EDR/AV Killer using truesight driver!" wide
        $ = "This is a PoC, use it at your own risk!" wide
        $ = "[-] Failed to set CTRL+C handler. Exiting..." wide
        $ = "ntdll.dll" wide
        $ = "\\\\.\\TrueSight" wide
        $ = "[-] CreateFileA failed" wide
        $ = " not running" wide
        $ = "[-] Process name: " wide
        $ = "[+] Terminating PID: " wide
        $ = "[-] DevicesIoControl failed" wide
        $ = "[!] Stoping and Deleting trueSight Service!" wide
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 1MB and filesize > 20KB and 
        20 of them
}
        