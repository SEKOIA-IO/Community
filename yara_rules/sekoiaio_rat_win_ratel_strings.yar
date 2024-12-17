rule sekoiaio_rat_win_ratel_strings {
    meta:
        id = "d0c8b89b-c811-47aa-9e03-717998c40d91"
        version = "1.0"
        description = "Detect RATel based on characteristic strings"
        author = "Sekoia.io"
        creation_date = "2023-04-24"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "[-] Error when changing folder." ascii
        $s2 = "cmd.exe" wide
        $s3 = "back slash find: " ascii
        $s4 = "MOD_ALL:" wide
        $s5 = "MOD_PERSISTENCE" wide
        $s6 = "MOD_DESTRUCTION:" wide
        $s7 = "MOD_RECONNECT" wide
        $s8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $s9 = "powershell.exe -command \"([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')\"" wide
        $s10 = "The command was executed successfully but no data was returned."
        $s11 = "[-] TIMEOUT IN CREATEPROCESS, but all the processes in the name of: " ascii
        $s12 = "we were well and truly killed." ascii
        
    condition:
        (uint16be(0) == 0x4d5a) and
        filesize > 500KB and filesize < 3MB and
        8 of them
}
        