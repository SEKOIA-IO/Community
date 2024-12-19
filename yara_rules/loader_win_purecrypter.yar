rule loader_win_purecrypter {
    meta:
        version = "1.0"
        description = "Detect the PureCrypter loader"
        author = "Sekoia.io"
        creation_date = "2022-09-22"
        id = "500b4d9e-55f8-41d1-ad4f-d587bbeb4507"
        classification = "TLP:CLEAR"
        
    strings:
        $hex01 = /http:\/\/[^\s]{5,90}_[A-Z][a-z]{7}\.(bmp|jpg|png)/ wide
        $hex02 = "WrapNonExceptionThrows" ascii
        
    condition:
        uint16(0)==0x5A4D and ($hex02 in (@hex01..@hex01 + 1000) or $hex01 in (@hex02..@hex02 + 1000))
}
        