rule apt_redhotel_maliciouslnk_strings {
    meta:
        id = "df2f0002-7921-4378-a936-ea0de5fbfa5a"
        version = "1.0"
        description = "Detects RedHotel's malicious LNKs"
        author = "Sekoia.io"
        creation_date = "2024-09-06"
        classification = "TLP:CLEAR"
        hash = "8e2c17040ec78cbcdc07bb2cf9dd7e01"
        hash = "dc613a519e515ca817fdfb88f81fc9d7"
        hash = "6f7d85c196c277a6a619f6d94b8f69b9"
        hash = "b04d484d1e1d793b04af2a5fb88a8a57"
        
    strings:
        $ = "desktop-" ascii
        $ = ".\\1.docx" wide
        $ = ".\\1.pdf" wide
        $ = ".\\1.doc" wide
        $ = ".\\1.ppt" wide
        $ = ".\\1.pptx" wide
        $ = "MACOS" wide
        
    condition:
        uint32be(0) == 0x4c000000 and 3 of them
}
        