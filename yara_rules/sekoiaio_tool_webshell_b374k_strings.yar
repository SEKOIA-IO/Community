rule sekoiaio_tool_webshell_b374k_strings {
    meta:
        id = "f53fc668-e1fc-4b85-b850-59aceefb6418"
        version = "1.0"
        description = "Detects b374k webshell"
        source = "Sekoia.io"
        creation_date = "2024-09-06"
        classification = "TLP:CLEAR"
        hash = "1d27b23fceecbb9e854c41f6a8fb878e"
        hash = "71fd853a3f3efc3dc2846e866187ee59"
        hash = "187e001c32487d0d68197ddb7e7796c3"
        hash = "6eac497dfc1020a8475e95542fad197e"
        hash = "61c6a0bc15efa442853f04bb276ac96e"
        
    strings:
        $ = "$func('$x','ev'.'al'.'("
        $ = "(ba'.'se'.'64'.'_de'.'co'.'de($x)))"
        
    condition:
        2 of them and filesize < 1MB
}
        