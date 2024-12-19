rule crime_sload_powershellarchiveexfiltrator_strings {
    meta:
        id = "3934696a-2116-49cb-9f75-3740767ad6f3"
        version = "1.0"
        author = "Sekoia.io"
        creation_date = "2022-08-02"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "if ($wr1 -or $wr2){"
        $ = "if ($zp1 -or $zp2){"
        $ = "-join ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_});"
        
    condition:
        all of them and filesize < 1KB
}
        