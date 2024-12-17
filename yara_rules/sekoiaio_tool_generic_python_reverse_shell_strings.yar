rule sekoiaio_tool_generic_python_reverse_shell_strings {
    meta:
        id = "5b926d15-4f21-428c-a9fa-ee085a98d42b"
        version = "1.0"
        description = "Detects reverse shell"
        author = "Sekoia.io"
        creation_date = "2024-04-16"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "import sys,socket,os,pty;"
        $ = "[os.dup2(s.fileno(),fd) for fd in (0,1,2)]"
        
    condition:
        all of them and filesize < 1000
}
        