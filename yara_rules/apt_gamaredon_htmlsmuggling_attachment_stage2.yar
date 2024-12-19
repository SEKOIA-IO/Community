rule apt_gamaredon_htmlsmuggling_attachment_stage2 {
    meta:
        id = "e82335ea-48d5-409c-a270-cfd5a2197c44"
        version = "1.0"
        description = "Detects Gamaredon HTMLSmuggling attachment"
        author = "Sekoia.io"
        creation_date = "2023-01-20"
        classification = "TLP:CLEAR"
        
    strings:
        $ = ") == -1) die();" ascii
        $ = "'data:application/x-rar-compressed;base64, ' +" ascii
        $ = ".appendChild(img);" ascii
        $ = "['Win32', 'Win64', 'Windows', 'WinCE'].indexOf(" ascii
        $ = " = navigator[\"platform\"];" ascii
        
    condition:
        4 of them and filesize < 1MB
}
        