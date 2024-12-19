rule apt_tealkurma_snappytcp_reverse_shell_strings {
    meta:
        id = "e842825c-546c-475a-bc94-7e97aea4e9e0"
        version = "1.0"
        description = "Detects TealKurma SnappyTCP reverse shell"
        author = "Sekoia.io"
        creation_date = "2023-12-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "2>&1>/dev/null&" ascii
        $ = ".php HTTP/1.1" ascii
        $ = "GET /" ascii
        $ = "Hostname: %s" ascii
        $ = "bash -c \"./" ascii
        
    condition:
        uint32be(0) == 0x7f454c46 and
        filesize < 3MB and
        3 of them
}
        