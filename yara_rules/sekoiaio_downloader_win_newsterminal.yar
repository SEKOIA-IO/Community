rule sekoiaio_downloader_win_newsterminal {
    meta:
        id = "2f9aae45-e3bd-4d87-b336-5d141738952b"
        version = "1.0"
        description = "Detect the PowerShell based downloader used by APT42 called NEWSTERMINAL"
        author = "Sekoia.io"
        creation_date = "2024-08-26"
        classification = "TLP:CLEAR"
        hash = "2b756515400d7e3b6e21ee3a83f313c8"
        
    strings:
        $ = "Start-Process -FilePath $takeownCommand -ArgumentList $takeownArgs -Wait -NoNewWindow"
        $ = "function Download-And-Extract-Dll {"
        // $icaclsArgs = $destinationFilePath, "/grant", "Administrators:F", "/c", "/q"
        $ = {24 69 63 61 63 6C 73 41 72 67 73 20 3D 20 24 64 65 73 74 69 6E 61 74 69 6F 6E 46 69 6C 65 50 61 74 68 2C 20 22 2F 67 72 61 6E 74 22 2C 20 22 41 64 6D 69 6E 69 73 74 72 61 74 6F 72 73 3A 46 22 2C 20 22 2F 63 22 2C 20 22 2F 71 22}
        $ = "$publicip=(iwr http://127.0.0.1:4040/api/tunnels"
        
    condition:
        1 of them and filesize < 30KB
}
        