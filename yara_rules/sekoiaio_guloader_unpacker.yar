rule sekoiaio_guloader_unpacker {
    meta:
        id = "dee4cad4-e3b4-4a12-860b-ff750b119fa8"
        version = "1.0"
        description = "GuLoader Unpacker"
        source = "Sekoia.io"
        creation_date = "2024-02-07"
        classification = "TLP:CLEAR"
        
    strings:
        $p1 = "([Parameter(Position = 0)] [Type[]] $" base64
        $p2 = "+=2){" base64
        $p3 = "}else {" base64
        
    condition:
        $p1 in (filesize-30000..filesize) and
        $p2 in (filesize-30000..filesize) and
        $p3 in (filesize-30000..filesize) and
        filesize > 300KB
}
        