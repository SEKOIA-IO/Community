import "pe"
        
rule sekoiaio_infostealer_win_aurora_str {
    meta:
        version = "1.0"
        description = "Finds Aurora botnet samples based on characteristic strings."
        source = "Sekoia.io"
        creation_date = "2022-07-21"
        id = "1f4391b8-700f-4702-9ef6-68ce3d55a176"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "Logs.tar" ascii
        $str02 = "*main.StealerData" ascii
        $str03 = "AppData\\Roaming\\Armory" ascii
        $str04 = "AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data" ascii
        $str05 = "github.com/TheTitanrain/w32" ascii
        $str06 = "github.com/mattn/go-sqlite3" ascii
        $str07 = "ScreenShot" ascii
        $str08 = "*sql.stmtConnGrabber" ascii
        $str09 = "Default\\Network\\Cookies" ascii
        $str10 = "BuildID" ascii
        $str11 = "Clipper" ascii
        $str12 = "GeoPos" ascii
        $str13 = "AppData\\Roaming\\Exodus\\exodus.wallet" ascii
        $str14 = "FileGrabber\\Documents" ascii
        $str15 = "193.233.48." ascii
        $str16 = "ShellExecute" ascii
        $str17 = "crypto/aes.(*aesCipherGCM).Encrypt" ascii
        $str18 = "File-Download" ascii
        
    condition:
        uint16(0)==0x5A4D and (14 of them or pe.imphash() == "8ee5c1c09f740fbe63e8b35dac5d6f70" or pe.imphash() == "369b4f5b6c99674f15070689e1f675af")
}
        