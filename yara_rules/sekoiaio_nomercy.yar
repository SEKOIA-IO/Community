rule sekoiaio_nomercy {
    meta:
        id = "2591f74b-8ab8-45ef-ba64-62a93df305c1"
        version = "1.0"
        hash1 = "9ecc76d4cda47a93681ddbb67b642c2e1f303ab834160ab94b79b47381e23a65"
        hash2 = "557acce8b787aba87c8eeb939438b52c5ca953f28ad680a7faeb2b3046d3fda0"
        description = "Detect NoMercy sample version up to 1.1.0"
        author = "Sekoia.io"
        creation_date = "2022-07-11"
        classification = "TLP:CLEAR"
        reference = "https://blog.cyble.com/2022/07/07/nomercy-stealer-adding-new-features/"
        
    strings:
        $debug1 = "Posted uid and version" wide ascii
        $debug2 = "Posted cli info to server" wide ascii
        $debug3 = "Posted other info to server" wide ascii
        $debug4 = "Sending screenshot..." wide ascii
        $debug5 = "Sent screenshot" wide ascii
        $debug6 = "Listening to Microphone..." wide ascii
        $debug7 = "Collecting other info..." wide ascii
        $url1 = "/a?uid=" wide ascii
        $url2 = "/c?uid=" wide ascii
        $url3 = "/d?uid=" wide ascii
        $url4 = "/e?uid=" wide ascii
        $url5 = "/b?sysinfoother=" wide ascii
        $url6 = "/b?sysinfocli=" wide ascii
        $info1 = "PUBLIC IP:" wide ascii
        $info2 = "HWID:" wide ascii
        $info3 = "RAM:" wide ascii
        $info4 = "GPU:" wide ascii
        $info5 = "MEDIA ACCESS CONTROL ADDRESS:" wide ascii
        $info6 = "PRIVATE IP:" wide ascii
        $info7 = "OS VERSION:" wide ascii
        $info8 = "ANTIVIRUS:" wide ascii
        $info9 = "KEYBOARD LANGUAGE:" wide ascii
        $info10 = "CLIPBOARD: {0}{1}{2}" wide ascii
        $info11 = "RUNNING PROCESSES:" wide ascii
        $info12 = "WINDOW TITLE:" wide ascii
        $cmd1 = "/c whoami /all" wide ascii
        $cmd2 = "/c whoami" wide ascii
        $cmd3 = "/c arp -a" wide ascii
        $cmd4 = "/c ipconfig /all" wide ascii
        $cmd5 = "/c net view /all" wide ascii
        $cmd6 = "/c net share" wide ascii
        $cmd7 = "/c route print" wide ascii
        $cmd8 = "/c netstat -nao" wide ascii
        $cmd9 = "/c net localgroup" wide ascii
        $cmd10 = "/c systeminfo" wide ascii
        $inv1 = "http://api.ipify.org" wide ascii
        $inv2 = "NoMercy" wide ascii
        
    condition:
    uint16be(0) == 0x4d5a 
    and 3 of ($debug*)
    and 8 of ($info*) 
    and 2 of ($url*)
    and 6 of ($cmd*) 
    and 1 of ($inv*) 
    and filesize > 700KB 
    and filesize < 3000KB
}
        