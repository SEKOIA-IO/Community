rule implant_lin_lightning {
    meta:
        id = "56f53e89-3b63-4ce7-a3c8-da0ba37246f1"
        version = "1.0"
        description = "Detect the Lightning framework (Core & Downloader plugin)"
        author = "Sekoia.io"
        creation_date = "2022-07-21"
        classification = "TLP:CLEAR"
        reference = "https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/"
        
    strings:
        $ = "{\"ComputerName\":\"%s\",\"Guid\":\"%s\",\"RequestName\":\"%s\",\"Licence\":\"%s\"}"
        $ = "kill -9 %s"
        $ = "{%08X-%04X-%04X-%04X-%04X%04X%04X}"
        $ = "sleep 60 && ./%s &"
        $ = "cat /sys/class/net/%s/address"
        $ = "/usr/bin/netstat"
        $ = "/usr/bin/whoami"
        $ = "/usr/bin/su"
        $ = "dup2: %s"
        $ = "Linux.Plugin.Kernel_%s"
        $ = "Lightning"
        
    condition:
        uint32(0)==0x464c457f
        and 9 of them
}
        