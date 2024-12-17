rule sekoiaio_apt_muddywater_muddyc2go_dll_launcher_strings {
    meta:
        id = "59756195-d842-4038-8fbf-43d26f4353bc"
        version = "1.0"
        description = "Detects MuddyC2Go DLL launcher"
        author = "Sekoia.io"
        creation_date = "2024-03-07"
        classification = "TLP:CLEAR"
        hash = "1a0827082d4b517b643c86ee678eaa53f85f1b33ad409a23c50164c3909fdaca"
        
    strings:
        $ = "-Method GET -ErrorAction Stop;Write-Output $response.Content;iex $response.Content;"
        $ = "GetCurrentProcess"
        $ = "TerminateProcess"
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 50KB and 
        all of them
}
        