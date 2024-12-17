rule sekoiaio_implant_win_quasarrat {
    meta:
        id = "492fdffc-8e5f-4225-a2eb-cd6d80e6bcb8"
        version = "1.0"
        description = "Detect QuasarRAT (reted from samples 2023-03)"
        author = "Sekoia.io"
        creation_date = "2023-03-17"
        classification = "TLP:CLEAR"
        reference = "https://blog.alyac.co.kr/5103"
        
    strings:
        // chcp 65001
        $ = {63 00 68 00 63 00 70 00 20 00 36 00 35 00 30 00 30 00 31 00}
        // echo DONT CLOSE THIS WINDOW!
        $ = {65 00 63 00 68 00 6f 00 20 00 44 00 4f 00 4e 00 54 00 20 00 43 00 4c 00 4f 00 53 00 45 00 20 00 54 00 48 00 49 00 53 00 20 00 57 00 49 00 4e 00 44 00 4f 00 57 00 21 00}
        // ping -n 10 localhost > nul
        $ = {70 00 69 00 6e 00 67 00 20 00 2d 00 6e 00 20 00 31 00 30 00 20 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 20 00 3e 00 20 00 6e 00 75 00 6c 00}
        // del /a /q /f "
        $ = {64 00 65 00 6c 00 20 00 2f 00 61 00 20 00 2f 00 71 00 20 00 2f 00 66 00 20 00 22 00}
        $ = "DoShellExecute"
        $ = "DoDownloadFile"
        
    condition:
        all of them
}
        