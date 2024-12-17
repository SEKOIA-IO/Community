rule sekoiaio_apt_gamaredon_htmlsmuggling_2024 {
    meta:
        id = "8fa1f80b-2261-4d63-92d8-7c360be73fe2"
        version = "1.0"
        description = "Detects HTML Smuggling webpages of Gamaredon used in 2024"
        author = "Sekoia.io"
        creation_date = "2024-09-09"
        classification = "TLP:CLEAR"
        hash = "ab2807824e68d5efb4c896e1af82e693"
        hash = "926b7e65d0d61cd6ba9e085193ae8b1d"
        
    strings:
        $ = "').innerHTML;window['" ascii fullword
        $ = "='at'+'ob';"
        $ = "]('*','');"
        $ = "display:none"
        $ = "0px;\" onerror=\""
        $ = "'ev'+'"
        $ = "<!DOCTYPE html PUBLIC"
        
    condition:
        5 of them and filesize < 1MB
}
        