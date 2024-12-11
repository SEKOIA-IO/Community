rule sekoiaio_loader_win_gcleaner {
    meta:
        version = "1.0"
        description = "Detect the GCleaner loader using specific strings"
        source = "Sekoia.io"
        creation_date = "2022-10-11"
        id = "0c085da3-ec77-4141-a927-bef1578a6dee"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "G-Cleaner can clean unneeded files, settings, and Registry entries" ascii
        $str02 = "3.  Click \"Run G-Cleaner\"" ascii
        $str03 = "Garbage_Cleaner" ascii
        $str04 = "GCleaner.Properties" ascii
        $str05 = "SOFTWARE\\GCleaner\\Install" wide
        $str06 = "SOFTWARE\\GCleaner\\Trial" wide
        $str07 = "SOFTWARE\\GCleaner\\License" wide
        $str08 = "G-Cleaner activation" wide
        
    condition:
        uint16(0)==0x5A4D and 6 of them
}
        