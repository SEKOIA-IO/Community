rule sekoiaio_infostealer_win_whitesnake_loader_feb23 {
    meta:
        id = "f81a8a96-6fd2-4f5c-8a56-ff66ff1a80d3"
        version = "1.0"
        description = "Finds WhiteSnake samples (loader module, bat file)"
        source = "Sekoia.io"
        creation_date = "2023-03-01"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "echo         Please wait... a while Loading data ...." ascii
        $str02 = "CERTUTIL -f -decode"  ascii
        $str03 = "%Temp%\\build.exe" ascii
        
        $crt = "-----BEGIN CERTIFICATE-----" ascii
        
        $mz = "TVqQAAMAAAAEAAAA" ascii
        
    condition:
        ($str01 in (0..200) or $str02 in (0..200) or $str03 in (0..200)) and
        $mz in (@crt..@crt+50) and
        filesize < 100KB
}
        