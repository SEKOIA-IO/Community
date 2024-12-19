rule infostealer_win_xehook_str {
    meta:
        id = "fa76988d-f0a2-4fc2-a122-c104fd585f34"
        version = "1.0"
        description = "Finds XehookStealer standalone samples based on specific strings."
        author = "Sekoia.io"
        creation_date = "2024-06-12"
        classification = "TLP:CLEAR"
        
    strings:
        $str01 = "xehook" ascii
        $str02 = "Classes.LogRecord" ascii
        $str03 = "__  _____| |__   ___   ___ | | __" wide
        $str04 = "\\ \\/ / _ \\ '_ \\ / _ \\ / _ \\| |/ /" wide
        $str05 = " >  <  __/ | | | (_) | (_) |   <" wide
        $str06 = "/_/\\_\\___|_| |_|\\___/ \\___/|_|\\_\\" wide
        $str07 = "https://t.me/xehook" wide
        $str08 = "About PC.txt" wide
        $str09 = "Browser: {4} v{5} ({6})" wide
        $str10 = "http://ip-api.com/json/?fields=11827" wide
        $str11 = "{0}gate.php?id={1}&build={2}&passwords={3}&cookies={4}" wide
        $str12 = "getjson.php?id=" wide
        
        $com01 = "CheckRemoteDebuggerPresent" ascii
        $com02 = "get_CurrentThread" ascii
        $com03 = "get_InstalledInputLanguages" ascii
        $com04 = "get_Ticks" ascii
        $com05 = "System.Security.Cryptography" ascii
        
    condition:
        uint16(0)==0x5A4D and 2 of ($str*) and 4 of ($com*)
}
        