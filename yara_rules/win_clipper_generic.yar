rule win_clipper_generic {
    meta:
        id = "a94b3d01-dbc7-41e4-8d45-793bf443b1d2"
        version = "1.0"
        description = "Clipper found during investigation: 892a9edb03db3fd88fecc1e1a2f56a7339f16f6734e8d77e6538ea2c8c9026d6"
        author = "Sekoia.io"
        creation_date = "2024-07-03"
        classification = "TLP:CLEAR"
        
    strings:
        // $ranpth = if ((Get-Random) % 2) { Join-Path $env:TEMP "$ran.ps1" } else { Join-Path $env:APPDATA "$ran.ps1" }
        $s = { 24 72 61 6e 70 74 68 20 3d 20 69 66 20 28 28 47 65 74 2d 52 61 6e 64 6f 6d 29 20 25 20 32 29 20 7b 20 4a 6f 69 6e 2d 50 61 74 68 20 24 65 6e 76 3a 54 45 4d 50 20 22 24 72 61 6e 2e 70 73 31 22 20 7d 20 65 6c 73 65 20 7b 20 4a 6f 69 6e 2d 50 61 74 68 20 24 65 6e 76 3a 41 50 50 44 41 54 41 20 22 24 72 61 6e 2e 70 73 31 22 20 7d  }
        
    condition:
        filesize > 1KB and
        all of them
}
        