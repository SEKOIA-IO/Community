rule tool_htran_strings {
    meta:
        id = "0184937e-eefa-4c6d-ae00-9b0af80dc7db"
        version = "1.0"
        description = "Detects HTran based on strings"
        author = "Sekoia.io"
        creation_date = "2022-09-09"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "-slave <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>"
        $ = "-tran <ConnectPort> <TransmitHost> <TransmitPort>"
        $ = "-listen <ConnectPort> <TransmitPort>"
        $ = "[-] There is a error...Create a new connection."
        $ = "[+] Start Transmit (%s:%d <-> %s:%d) ......"
        $ = "[+] Accept a Client on port %d from %s"
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        3 of them
}
        