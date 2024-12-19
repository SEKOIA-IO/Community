rule crypter_win_dotrunpex {
    meta:
        id = "6fb4ffe0-3a5c-432c-8ae2-404bb5960c30"
        version = "1.0"
        description = "Detect the dotRunpeX crypter based on strings"
        author = "Sekoia.io"
        creation_date = "2023-06-08"
        classification = "TLP:CLEAR"
        
    strings:
        $ = {52 00 75 00 6e 00 70 00 65 00 58 00 2e 00 53 00 74 00 75 00 62 00 2e 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 2e 00 65 00 78 00 65} //R.u.n.p.e.X...S.t.u.b...F.r.a.m.e.w.o.r.k...e.x.e
        
    condition:
        uint16(0)==0x5A4D and all of them
}
        