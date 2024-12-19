rule infostealer_win_enigma_loader_module {
    meta:
        id = "664fe8de-b406-4d63-9a4b-1c350b444f01"
        version = "1.0"
        description = "Find loader module of Enigma Stealer based on specific strings"
        author = "Sekoia.io"
        creation_date = "2023-01-30"
        classification = "TLP:CLEAR"
        hash = "f1623c2f7c00affa3985cf7b9cdf25e39320700fa9d69f9f9426f03054b4b712"
        
    strings:
        $str01 = "Enigma.Loader.Driver_x64.dll" ascii
        $str02 = "C:\\projects\\driver\\Driver\\x64\\Release\\driver.pdb" ascii
        $str03 = "/getFile?file_id=" ascii
        $str04 = "/file/bot" ascii
        $str05 = "Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator." wide
        $str06 = "[GetTgFileById][GetTgRequest] reply is NULL" wide
        $str07 = "Telegram request failed" wide
        $str08 = "Vul driver data destroyed before unlink" wide
        $str09 = "GetExportAddress hash not found: %x" wide
        $str10 = "\\REGISTRY\\MACHINE\\HARDWARE\\RESOURCEMAP\\PnP Manager\\PnpManager" wide
        
    condition:
        uint16(0)==0x5A4D and 4 of them
}
        