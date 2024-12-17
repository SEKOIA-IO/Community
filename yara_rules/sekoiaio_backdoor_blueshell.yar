rule sekoiaio_backdoor_blueshell {
    meta:
        id = "8f1cd966-c4d8-44f9-8cd5-4f5277332546"
        version = "1.0"
        description = "Detects BlueShell backdoor"
        author = "Sekoia.io"
        creation_date = "2023-09-08"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "BlueShell" ascii
        $s2 = "client.go" ascii
        $s3 = "server ip" ascii
        $s4 = "server port" ascii
        $s5 = "reconnect wait time" ascii
        $s6 = "shell" ascii
        $s7 = "socks" ascii
        $s8 = "socks5" ascii
        $s9 = "GetInteractiveShell" ascii
        
    condition:
        filesize < 11MB and all of them
}
        