rule apt_gamaredon_powerrevshell {
    meta:
        id = "b5161c23-c607-4096-9f4a-1be516a0a614"
        version = "1.0"
        description = "Detects Powershell reverse shell"
        author = "Sekoia.io"
        creation_date = "2023-02-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "iex $enc.GetString("
        $ = "$stream.Write"
        $ = ".).FullName"
        $ = "Sockets.TcpClient"
        $ = "\">\";"
        
    condition:
        all of them and filesize < 3000
}
        