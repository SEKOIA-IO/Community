rule sekoiaio_apt_tortoiseshell_wateringhole_script {
    meta:
        id = "58c5ae66-fe09-497c-80bf-20feee4d95e7"
        version = "1.0"
        description = "Detect's Tortoiseshell WH script"
        source = "Sekoia.io"
        creation_date = "2023-05-24"
        classification = "TLP:CLEAR"
        
    strings:
        $ = "btoa(pluggin.toString())"
        $ = "btoa(document.referrer)"
        $ = "pluggin.push(navigator.plugins[i]"
        $ = "navigator.language"
        $ = "window.RTCPeerConnection"
        $ = "sha256(canvas.toDataURL("
        $ = "canvas.getContext('2d"
        $ = "noop = function() {},"
        
    condition:
        5 of them and filesize < 10000
}
        