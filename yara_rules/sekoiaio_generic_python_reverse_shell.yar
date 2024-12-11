rule sekoiaio_generic_python_reverse_shell {
    meta:
        id = "ab25f8db-e39d-4aa4-b431-cf5cd2e038e5"
        version = "1.0"
        description = "Detects simple reverse shell written in Python"
        source = "Sekoia.io"
        creation_date = "2023-12-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "import pty"
        $ = "lhost ="
        $ = "os.dup2(s.fileno(),0)"
        $ = "os.putenv(\"HISTFILE\",'/dev/null')"
        
    condition:
        filesize < 1KB and all of them
}
        