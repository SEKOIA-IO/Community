rule vpn_mul_softether {
    meta:
        id = "a1fbf4fe-b934-4a66-b6b1-ebe2f83505cd"
        version = "1.0"
        description = "Detect the open-source SoftEther VPN"
        author = "Sekoia.io"
        creation_date = "2024-04-15"
        classification = "TLP:CLEAR"
        reference = "https://www.softether.org/"
        
    strings:
        $ = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\softether_se%s"
        $ = "GET /vgc_download_dat/ HTTP/1.1"
        $ = "http://x%c.x%c.client.api.vpngate2.jp/api/"
        $ = "http://x0.x0.client.api.vpngate2.jp/check/check.txt"
        $ = "https://x%c.x%c.statistics.api.vpngate2.jp/api/statistics/"
        $ = "Software\\SoftEther Project\\SoftEther VPN\\"
        
        $ = "|vpnsetup_nosign.exe" wide
        $ = "/ISEASYINSTALLER:%u" wide
        $ = "/CALLERSFXPATH:\"%s\"" wide
        $ = "vpn_client.config" wide
        $ = "vpn_bridge.config" wide
        $ = "|backup_dir_readme.txt" wide
        $ = "vpn_debuginfo_%04u%02u%02u_%02u%02u%02u.zip" wide
        
    condition:
        8 of them
}
        