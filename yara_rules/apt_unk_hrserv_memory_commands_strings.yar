rule apt_unk_hrserv_memory_commands_strings {
    meta:
        id = "1b5f442a-e758-4bd5-a612-8b504a542d29"
        version = "1.0"
        description = "Detects HrServ web shell memory commands"
        author = "Sekoia.io"
        creation_date = "2023-11-23"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "list all the process" ascii wide
        $ = "equal with cmd /c tasklist" ascii wide
        $ = "start target service by name" ascii wide
        $ = "query local process information by wmi." ascii wide
        $ = "upload local shellcode to" ascii wide
        
    condition:
        all of them
}
        