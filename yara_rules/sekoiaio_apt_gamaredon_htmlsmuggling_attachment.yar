rule sekoiaio_apt_gamaredon_htmlsmuggling_attachment {
    meta:
        id = "a39b6e67-9327-4c5b-902a-b9853cfefc8e"
        version = "1.0"
        description = "Detects Gamaredon HTMLSmuggling attachment"
        author = "Sekoia.io"
        creation_date = "2023-01-20"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "['at'+'ob'](" ascii
        $ = "['ev'+'al'](" ascii
        $ = "document.querySelectorAll('[" ascii
        $ = "[0].innerHTML.split(' ').join('')))" ascii
        
    condition:
        filesize < 1MB and
        2 of them
}
        