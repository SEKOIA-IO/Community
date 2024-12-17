rule sekoiaio_apt_lazarus_backdoored_jslib {
    meta:
        id = "73ffd449-93c8-494e-9c14-2e933b21a200"
        version = "1.0"
        description = "Detects InvisibleFerret based on common ressource."
        author = "Sekoia.io"
        creation_date = "2024-10-28"
        classification = "TLP:CLEAR"
        hash = "52e92be527690f4e63608cbc699e2f70"
        
    strings:
        $obf = "(function(_0x" ascii
        $exp = "module.exports =" ascii
        
    condition:
        $exp in (filesize-500..filesize) and #obf == 1
}
        