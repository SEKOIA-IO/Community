rule sekoiaio_pe_princeransomware_strings {
    meta:
        id = "9c5cad6e-2b11-469c-ace1-2dc51562b035"
        version = "1.0"
        description = "Prince Ransomware exe files"
        author = "Sekoia.io"
        creation_date = "2024-08-07"
        classification = "TLP:CLEAR"
        hash = "8bd8de169f45e32bab53f6e06088836d6f0526105f03efa1faf84f3b02c43011"
        hash = "a83aad6861c8fdfe2392b8e286ab7051d223c6b0bbba5996165964f429657a37"
        
    strings:
        $ = "https://i.imgur.com/RfsCOES.png" ascii
        $ = {596f75722066696c65732068617665206265656e20656e63727970746564207573696e67205072696e63652052616e736f6d77617265} //Your files have been encrypted using Prince Ransomware
        
    condition:
        all of them and uint16(0) == 0x5a4d and filesize > 1MB
}
        