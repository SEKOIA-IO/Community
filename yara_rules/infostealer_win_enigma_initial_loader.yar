rule infostealer_win_enigma_initial_loader {
    meta:
        id = "664fe8de-b406-4d63-9a4b-1c350b444f00"
        version = "1.0"
        description = "Find initial loader of Enigma Stealer based on specific strings"
        author = "Sekoia.io"
        creation_date = "2023-01-30"
        classification = "TLP:CLEAR"
        hash = "03b9d7296b01e8f3fb3d12c4d80fe8a1bb0ab2fd76f33c5ce11b40729b75fb23"
        
    strings:
        $str01 = "/getFile?file_id=" ascii
        $str02 = "/file/bot" ascii
        $str03 = "?file_id=" ascii
        $str04 = "pInternetSetOptionA failed" wide
        $str05 = "list_messages[file_path] failed" wide
        $str06 = "iE&xit" wide
        $str07 = "[GetTgFileById][GetTgRequest] reply is NULL" wide
        $str08 = "Telegram request failed" wide
        $str09 = "bot getted" wide
        
    condition:
        uint16(0)==0x5A4D and 4 of them
}
        