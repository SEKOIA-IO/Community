import "magic"
        
rule bumblebee_vhd {
    meta:
        id = "0a9d1ffa-a3ff-4b15-b660-b4c132d5a415"
        version = "1.0"
        description = "BumbleBee new infection vector via VHD file and powershell second stage"
        author = "Sekoia.io"
        creation_date = "2022-09-09"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" ascii
        $s2 = "Invalid partition table" ascii
        $s3 = "BOOTMGR" ascii
        $s4 = "LNK" ascii
        
    condition:
        magic.mime_type() == "application/x-virtualbox-vhd" and
        filesize > 3MB and filesize < 10MB and
        all of ($s*)
}
        