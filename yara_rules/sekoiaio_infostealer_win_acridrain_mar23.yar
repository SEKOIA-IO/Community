rule sekoiaio_infostealer_win_acridrain_mar23 {
    meta:
        id = "049b502a-0fb6-4fa9-a1ce-f01a40269bdb"
        version = "1.0"
        description = "Finds AcridRain samples"
        author = "Sekoia.io"
        creation_date = "2023-03-21"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "\",\"r\":" ascii
        $str02 = "\",\"s\":\"" ascii
        $str03 = "\",\"p\":\"" ascii
        $str04 = "\",\"a\":\"" ascii
        $str05 = ",\"c\":" ascii
        $str06 = ",\"g\" :" ascii
        $str07 = "v7166637466625297979 t2537736810932639330 ath5ee645e0 altpriv cvcv=2 cexpw=1 smf=0" ascii
        $str08 = "Content-Type: multipart/form-data; boundary=----974767299852498929531610575" ascii
        $str09 = "\\Roaming\\Bitwarden\\data\\bitwarden.sqlite3" ascii
        
        $ste01 = "\\Roaming\\Exodus\\exodus.wallet" ascii
        $ste02 = "\\Roaming\\Electron Cash\\wallets" ascii
        $ste03 = "\\Roaming\\com.liberty.jaxx\\IndexedDB\\file__0.indexeddb.leveldb" ascii
        $ste04 = "\\Local Extension Settings\\" ascii
        $ste05 = "cnmamaachppnkjgnildpdmkaakejnhae" ascii
        $ste06 = "ffnbelfdoeiohenkjibnmadjiehjhajb" ascii
        $ste07 = "\\formhistory.sqlite" ascii
        $ste08 = "\\logins.json" ascii
        $ste09 = "encrypted_key" ascii
        $ste10 = "\\Login Data" ascii
        
        $enc01 = "bX5cVw8FKyAKZVxXXUAdSTUXCXdCV0FoOxoSF0ZEUEZS" ascii
        $enc02 = "bX5cVw8FKywUaVVbRlkyPAQAFCB1U0dV" ascii
        $enc03 = "bX5cVw8FKzQvUBFhRkYINSIWA3IRdlJADw==" ascii
        $enc04 = "bX5cVw8FKzYWdUVcWl8iCBU5NXBERl1dBTUiFgNyEXZSQA8=" ascii
        $enc05 = "bWBcVQMAGQI6UEJbGGgeGxgDD2xUQW9QCw8WEAp0" ascii
        
    condition:
        uint16(0) == 0x5A4D and 5 of ($str*) and 7 of ($ste*) and 1 of ($enc*)
}
        