import "pe"
import "hash"
        
rule sekoiaio_backdoor_win_headertip {
    meta:
        id = "82899406-4ec3-41d2-bcc1-bdd1ee440e77"
        version = "1.0"
        description = "Detect HeaderTip backdoor used by the Chinese threat actor Scarab. This backdoor has its hardcoded C2 in strings"
        author = "Sekoia.io"
        creation_date = "2022-03-25"
        classification = "TLP:CLEAR"
        hash1 = "e1523185eac41a615b8d2af8b7fd5fe07b755442df2836041be544dff6881237"
        hash2 = "da8a98d9b9a3c176ba44fb69ad0a820a971950e05f1eb0c4bbbf6c2fbb748bdc"
        hash3 = "63a218d3fc7c2f7fcadc0f6f907f326cc86eb3f8cf122704597454c34c141cf1"
        
    strings:
        $post = "POST" wide
        $ua = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" wide
        
    condition:
        (uint16(0)==0x5A4D and $post at 7256 and $ua at 7304 and filesize < 10KB)
        or pe.imphash() == "60d01115d6baa0f214990c6e19339133"
        or hash.md5(pe.rich_signature.clear_data) == "48f9cf422144c033e2ca183f72587910"
}
        