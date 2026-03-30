rule phishing_eviltokens_phishing_page {
    meta:
        malware = "EvilTokens"
        description = "Find EvilTokens device code phishing pages based on characteristic strings"
        source = "Sekoia.io"
        creation_date = "2026-03-05"
        modification_date = "2026-03-05"
        classification = "TLP:CLEAR"
        reference = "https://blog.sekoia.io/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1/"


    strings:
        $html = "<!DOCTYPE html>" ascii

        $str01 = "<div id=\"r\">" ascii
        $str02 = "function f(s){" ascii
        $str03 = "return Uint8Array.from(atob(s),x=>x.charCodeAt(0))" ascii
        $str04 = "var k=await crypto.subtle.importKey(" ascii
        $str05 = "var p=await crypto.subtle.decrypt(" ascii
        $str06 = "name:\"AES-GCM\",iv:f(b)" ascii
        $str07 = "document.write(new TextDecoder().decode(" ascii
        $str08 = "document.body.innerHTML=\"Loading failed\"" ascii
        $str09 = "document.close()}catch(e)" ascii

    condition:
        $html at 0 and
        6 of them and filesize < 50KB
}
