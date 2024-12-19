rule apt_gamaredon_ddrdoh_vbs_downloader_vbs {
    meta:
        id = "cc29d5d9-58bd-4f68-8673-daa41abfc7be"
        version = "1.0"
        description = "Detects malicious VBScript executed by LNK/mshta"
        author = "Sekoia.io"
        creation_date = "2023-01-24"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "b24gZXJyb3IgcmVzd" ascii
        $ = "BinaryStream.readtext" ascii nocase
        $ = "createobject(\"msxml2.domdocument.3.0\").createelement(" ascii nocase
        $ = "Dim cSecond, cMinute, CHour, cDay, cMonth, cYear" ascii nocase
        $ = "tDate & \"T\" & tTime"
        $ = "AutoOpen" ascii nocase
        
    condition:
        5 of them and filesize < 50KB
}
        