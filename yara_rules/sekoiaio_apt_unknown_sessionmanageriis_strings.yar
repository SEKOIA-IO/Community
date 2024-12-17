rule sekoiaio_apt_unknown_sessionmanageriis_strings {
    meta:
        id = "7d55dd82-509f-444d-a1ba-6417b51f392f"
        version = "1.0"
        description = "Detects the IIS SessionManager backdoor"
        author = "Sekoia.io"
        creation_date = "2022-07-04"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Wokring OK"
        $ = "Delete File Success :"
        $ = "Delete File Error :"
        $ = "SM_SESSION="
        $ = "SM_SESSIONID"
        $ = "attachment; filename ="
        $ = "CHttpModule::"
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize > 100KB and filesize < 400KB and
        4 of them
}
        