rule sekoiaio_infostealer_win_leaf {
    meta:
        id = "17d8e384-1092-4f27-b4f7-c0c0f7efcaa3"
        version = "1.0"
        description = "Find samples of Leaf Stealer based on specific strings"
        source = "Sekoia.io"
        creation_date = "2023-02-07"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "Leaf $tealer" ascii
        $str02 = "KiwiFolder" ascii
        $str03 = "key_wordsFiles" ascii
        $str04 = "**[Click to copy](https://superfurrycdn.nl/copy/" ascii
        $str05 = "Early_Verified_Bot_Developer" ascii
        $str06 = "getCookie.<locals>.<genexpr>" ascii
        $str07 = "C:\\Program Files (x86)\\Steam\\config" ascii
        $str08 = "[crunchyroll](https://crunchyroll.com)" ascii
        $str09 = "-m pip install" ascii
        $str10 = "taskkill /im " ascii
        $str11 = "/loginusers.vdf" ascii
        $str12 = "mot_de_passe" ascii
        $str13 = "Interesting files found on user PC" ascii
        $str14 = "NationsGlory/Local Storage/leveldb" ascii
        $str15 = "wppassw.txt" ascii
        $str16 = "wpcook.txt" ascii
        $str17 = "ProcesName < 1 >" ascii
        $str18 = "Metamask_" ascii
        
    condition:
        uint16(0)==0x5A4D and 10 of them
}
        