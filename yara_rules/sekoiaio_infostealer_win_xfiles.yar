rule sekoiaio_infostealer_win_xfiles {
    meta:
        id = "3ad3ee19-6be8-484b-943c-05813cdcbd18"
        version = "1.0"
        description = "Detect the X-FILES infostealer based on specific strings"
        source = "Sekoia.io"
        reference = "https://twitter.com/3xp0rtblog/status/1375206169384521730"
        creation_date = "2022-02-03"
        classification = "TLP:CLEAR"
        
    strings:
        $xfi0 = "Telegram bot - @XFILESShop_Bot" wide
        $xfi1 = "Telegram support - @XFILES_Seller" wide
        
        $brw0 = "\\Google\\Chrome\\User Data\\Default\\Network\\Cookies" wide
        $brw1 = "\\Chromium\\User Data\\Default\\Cookies" wide
        $brw2 = "\\Slimjet\\User Data\\Default\\Cookies" wide
        $brw3 = "\\Vivaldi\\User Data\\Default\\Cookies" wide
        $brw4 = "\\Opera Software\\Opera GX Stable\\Cookies" wide
        $brw5 = "\\Opera Software\\Opera Stable\\Cookies" wide
        
        $crp00 = "Tronlink" wide
        $crp01 = "NiftyWallet" wide
        $crp02 = "MetaMask" wide
        $crp03 = "MathWallet" wide
        $crp04 = "Coinbase" wide
        $crp05 = "BinanceChain" wide
        $crp06 = "GuardaWallet" wide
        $crp07 = "EqualWallet" wide
        $crp08 = "BitAppWallet" wide
        $crp09 = "iWallet" wide
        $crp10 = "Wombat" wide
        $crp11 = "Zcash" wide
        $crp12 = "Armory" wide
        $crp13 = "Bytecoin" wide
        $crp14 = "Jaxx" wide
        $crp15 = "Exodus" wide
        $crp16 = "Ethereum" wide
        $crp17 = "AtomicWallet" wide
        $crp18 = "Guarda" wide
        $crp19 = "Coinomi" wide
        $crp20 = "Litecoin" wide
        $crp21 = "Dash" wide
        $crp22 = "Bitcoin" wide
        
    condition:
        uint16(0)==0x5A4D and 
        any of ($xfi*) or 
        5 of ($brw*) and 20 of ($crp*)
}
        