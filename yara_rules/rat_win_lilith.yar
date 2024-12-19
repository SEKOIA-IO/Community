rule rat_win_lilith {
    meta:
        id = "944637e6-c4e4-423f-9f4c-a26b4fce3729"
        version = "1.0"
        description = "Detect the Lilith malware"
        author = "Sekoia.io"
        creation_date = "2023-02-23"
        classification = "TLP:CLEAR"
        
    strings:
        // UmVnUXVlcnlWYWx1ZUV4QQ==
        $ = {55 6d 56 6e 55 58 56 6c 63 6e 6c 57 59 57 78 31 5a 55 56 34 51 51 3d 3d}
        // getaddrinfo: %s
        $ = {67 65 74 61 64 64 72 69 6e 66 6f 3a 20 25 73}
        
    condition:
        all of them
}
        