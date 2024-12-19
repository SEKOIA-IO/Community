rule apt_darkpink_kamikakabot_strings {
    meta:
        id = "0f5a7d72-81c8-4fdd-aefd-136bc6d48aa5"
        version = "1.0"
        description = "Detects KamiKakaBot strings (.NET sample of Dark Pink)"
        author = "Sekoia.io"
        creation_date = "2023-02-22"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "Execute"
        $ = "f4869"
        $ = "getIndentifyName"
        $ = "getMessageAsync"
        $ = "requestMessageID"
        $ = "run_command"
        $ = "sendFile"
        $ = "sendMessage"
        $ = "send_brw_data"
        $ = "updateMessageID"
        $ = "update_new_token"
        $ = "update_new_xml"
        $ = {53 00 74 00 61 00 72 00 74 00 65 00 64 00 20 00 75 00 70 00 20 00 72 00 75 00 6e}
        $ = {20 00 72 00 65 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 65 00 64 00 21}
        $ = {6e 00 65 00 77 00 20 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 65 00 64 00 21}
        $ = {74 00 6f 00 6b 00 65 00 6e 00 20 00 75 00 70 00 64 00 61 00 74 00 65 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 21 00 21 00 21}
        
    condition:
       6 of them
}
        