rule sekoiaio_apt_gamaredon_gamaredon_lnk_usb_spreader {
    meta:
        id = "a0972e30-bfc5-48ff-b04b-382db8c08a54"
        version = "1.0"
        description = "Detects Gamaredon LNK USB Spreader"
        author = "Sekoia.io"
        hash = "2aee8bb2a953124803bc42e5c42935c92f87030b65448624f51183bf00dd1581"
        creation_date = "2023-06-19"
        classification = "TLP:CLEAR"
        
    strings:
        $ = ".CREatesHoRTCUt(" nocase ascii wide
        $ = "cOPY-Item $enV:UsErprOfilE" nocase ascii wide
        $ = "-dEsTInaTioN $Env:" nocase ascii wide
        $ = " = GET-ChilDITem $drivE.nAMe" nocase ascii wide
        $ = "STArt-SLEeP" nocase ascii wide
        $ = "-eq [SYsTEM.Io.fILeaTTrIbuTES]::DIRecToRy" nocase ascii wide
        $ = "drIvETYPe='2'" nocase ascii wide
        $ = ".iConloCaTiON = " nocase ascii wide
        
    condition:
        7 of them
}
        