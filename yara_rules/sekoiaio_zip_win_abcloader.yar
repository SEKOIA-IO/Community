rule sekoiaio_zip_win_abcloader {
    meta:
        id = "0d14b34a-9095-48fa-b616-4e8239f3b547"
        version = "1.0"
        description = "Use the CRC32 to detect a zip containing the doc file used to drop and launch ABCloader"
        source = "Sekoia.io"
        creation_date = "2024-08-19"
        classification = "TLP:CLEAR"
        hash = "0c7d8e611781b29e15df415640858294"
        
    strings:
        $crc = {32 56 27 e2}
        $name = "iden.doc"
        
    condition:
        $name at @crc[1] + 16
}
        