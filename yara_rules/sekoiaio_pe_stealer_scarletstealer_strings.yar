rule sekoiaio_pe_stealer_scarletstealer_strings {
    meta:
        id = "ca930851-513f-44e5-abb4-ca0edfde3428"
        version = "1.0"
        description = "ScarletStealer strings"
        source = "Sekoia.io"
        creation_date = "2023-12-15"
        classification = "TLP:CLEAR"
        
    strings:
        $s1 = "Scarlet Client" wide
        $s2 = "] PC NAME:   (" wide
        $s3 = "] IP:   (" wide
        $s4 = " - Wallets -" wide
        $s5 = "] Exodus:  (" wide
        $s6 = "] Electrum:  (" wide
        $s7 = "] Atomic:  (" wide
        $s8 = "] Guarda:  (" wide
        $s9 = "] Coinomi: (" wide
        $s10 = "] Monero:  (" wide
        $s11 = "] Ledger:  (" wide
        $s12 = "] Bitbox:  (" wide
        $s13 = "] Trezor:  (" wide
        $s14 = ") Support: PointX@exploit.im - @isPointX" wide
        $a2 = "/config/tk.txt" wide
        $a3 = "/config/chatid.txt" wide
        $a1 = "telebyt.com" wide
        
    condition:
        uint16be(0) == 0x4d5a and
        filesize > 50KB and filesize < 2MB and
        13 of ($s*) and 2 of ($a*)
}
        