rule crypter_vbs_to_exe {
    meta:
        id = "33ed286f-3055-452e-952b-abaf11a543a1"
        version = "1.0"
        description = "first stage of Crypter-VBS-to-EXE dropped on infected hosted"
        author = "Sekoia.io"
        creation_date = "2023-01-03"
        classification = "TLP:CLEAR"
        
    strings:
        $theDot = ":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::" ascii
        $s1 = "cmd.exe /c curl" ascii
        $s2 = "WScript.Sleep(3000)" ascii
        $s3 = "runCmd = \"cmd.exe /c powershell.exe -exec Bypass -C \" + myVar +" ascii
        $s4 = "WshShell.Run \"cmd /c \" & runCmd, 0, True" ascii
        
    condition:
        #theDot > 200  and all of ($s*)
}
        