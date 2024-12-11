rule sekoiaio_ransomware_win_shrinklocker {
    meta:
        id = "93a6fbdd-ad62-456a-a1a5-b5ae3b242004"
        version = "1.0"
        description = "Detects files related to the ShrinkLocker ransomware"
        source = "Sekoia.io"
        creation_date = "2024-06-07"
        classification = "TLP:CLEAR"
        
    strings:
        $a = "shrinkdisk" ascii fullword
        $b = "BitLocker" ascii fullword
        $c = "diskpart" ascii fullword
        $d = "disk.vbs" ascii fullword
        $e = "strDriveLetter" ascii fullword
        $f = "shrinkcomplate" ascii fullword
        $g = "ADODB.Stream" ascii fullword
        $h = "Win32_OperatingSystem" ascii fullword
        $i = "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server" ascii fullword
        $j = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii fullword
        $k = "HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE" ascii fullword
        
    condition:
        9 of them
}
        