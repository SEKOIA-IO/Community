rule crime_sload_mainpowershellimplant {
    meta:
        id = "09d268e7-d688-4390-856e-9e9ed47aec04"
        version = "1.0"
        description = "Detects the main PowerShell implant"
        author = "Sekoia.io"
        creation_date = "2022-08-03"
        classification = "TLP:CLEAR"
        
    strings:
        $c1 = "priority FOREGROUND"
        $c2 = "app|Services|RuntimeBroker|Search|host"
        $c3 = "([wmiclass]\"win32_Process\").create("
        $c4 = "Start-Sleep -seconds"
        $c5 = "while($e -eq 1){ $dCnt++;"
        
        $d1 = "112,114,105,111,114,105,116,121,32,70,79,82,69,71,82,79,85,78,68"
        $d2 = "97,112,112,124,83,101,114,118,105,99,101,115,124,82,117,110,116,105,109,101,66,114,111,107,101,114,124,83,101,97,114,99,104,124,104,111,115,116"
        $d3 = "40,91,119,109,105,99,108,97,115,115,93,34,119,105,110,51,50,95,80,114,111,99,101,115,115,34,41,46,99,114,101,97,116,101,40"
        $d4 = "83,116,97,114,116,45,83,108,101,101,112,32,45,115,101,99,111,110,100,115"
        $d5 = "119,104,105,108,101,40,36,101,32,45,101,113,32,49,41,123,32,36,100,67,110,116,43,43,59"
        
        $b1 = "priority FOREGROUND" base64
        $b2 = "app|Services|RuntimeBroker|Search|host" base64
        $b3 = "([wmiclass]\"win32_Process\").create(" base64
        $b4 = "Start-Sleep -seconds" base64
        $b5 = "while($e -eq 1){ $dCnt++;" base64
        
    condition:
        3 of ($c*) or 3 of ($d*) or 3 of ($b*) and filesize < 30KB
}
        