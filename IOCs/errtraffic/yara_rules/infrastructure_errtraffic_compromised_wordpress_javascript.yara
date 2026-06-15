rule phishing_errtraffic_compromised_wordpress_javascript {
    meta:
        description = "Compromised WordPress HTML embedding ErrTraffic initial script"
        source = "Sekoia.io"
        creation_date = "2026-04-24"
        modification_date = "2026-04-24"
        classification = "TLP:CLEAR"

    strings:
        $html = "<!doctype html>" nocase

        $var01 = { 3c 73 63 72 69 70 74 3e 28 66 75 6E 63 74 69 6F 6E 28 29 7B 76 61 72 20 [1] 3D [1-3] 2C [1] 3D } //<script>(function(){var k=178,d="
        $var02 = { 3c 73 63 72 69 70 74 3e 28 66 75 6E 63 74 69 6F 6E 28 29 7B 76 61 72 20 5F 30 78 ?? ?? ?? ?? ?? ?? 3D [1-3] 3B 76 61 72 20 5F 30 78 ?? ?? ?? ?? ?? ?? 3D } //<script>(function(){var _0xf90e0f=178; var _0x0d2f63="

        $str01 = "=atob(" ascii
        $str02 = "=new Uint8Array(" ascii
        $str03 = ".charCodeAt(i)^" ascii
        $str04 = "new TextDecoder().decode(" ascii
        $str05 = "new Function(" ascii
        $str06 = "String.fromCharCode(" ascii

    condition:
        $html and 1 of ($var*) and 5 of ($str*)
}