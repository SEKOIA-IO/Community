rule sekoiaio_implant_win_quantum_builder_lnk {
    meta:
        id = "65f8a426-8bf3-4f7f-b7d2-fd8da5b660f7"
        version = "1.0"
        description = "Detect .LNK files created using Quantum Builder"
        author = "Sekoia.io"
        creation_date = "2022-06-22"
        classification = "TLP:CLEAR"
        
    strings:
        $magic_lnk = { 4C 00 00 00 01 14 02 00 }
        $powershell_ascii = "\\WindowsPowerShell\\v1.0\\powershell.exe"
        $powershell_wide = "powershell.exe" wide
        
        $start = "<#" wide
        $end = "#>" wide
        $foreach = "=$Null;foreach(" wide
        $return = "};return" wide
        $char = "[char]" wide
        
        $aes = "New-Object 'System.Security.Cryptography.AesManaged'" wide nocase
        $base64 = "[System.Convert]::FromBase64String" wide nocase
        $decryptor = "CreateDecryptor();" wide nocase
        
    condition:
        $magic_lnk at 0
        and all of ($powershell*)
        
        and (
            // Obfuscated
            $start
            and $end
            and $foreach
            and $return
            and $char
            
            or
            
            // AES + Base64
            $aes
            and $base64
            and $decryptor
        )
}
        