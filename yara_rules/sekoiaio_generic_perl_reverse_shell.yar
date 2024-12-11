rule sekoiaio_generic_perl_reverse_shell {
    meta:
        id = "4eb2ef0d-3ada-4566-bd82-8c75d6931acc"
        version = "1.0"
        description = "Detects simple reverse shell written in Perl"
        source = "Sekoia.io"
        creation_date = "2023-12-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "open(STDIN,\">&S\");"
        $ = "open(STDERR,\">&S\");"
        $ = "use Socket;$i="
        
    condition:
        filesize < 300 and all of them
}
        