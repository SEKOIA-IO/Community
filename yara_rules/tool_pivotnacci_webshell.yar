rule tool_pivotnacci_webshell {
    meta:
        id = "729b6381-b59d-46fe-9ad4-b8b68fb0ceea"
        version = "1.0"
        description = "Detects pivotnacci webshell"
        author = "Sekoia.io"
        creation_date = "2024-04-22"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "if (cmd == SEND_OPERATION) {"
        $ = "Response.BinaryWrite(newBuff)"
        $ = "Request.Headers.Get(ID_HEADER)"
        $ = "[$READ_BUFFER_SESSION_KEY . $connection_id]"
        $ = "extract_session_readbuf($conn_id"
        $ = "Failed connecting to target $addr:$port : $errstr"
        $ = "void handle_post(String cmd)"
        $ = "SocketChannel socketChannel = this.get_socket(socket_id"
        $ = "this.get_svc().compareTo(this.get_hostname())"
        
    condition:
        3 of them and filesize < 10KB
}
        