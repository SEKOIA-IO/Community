rule sekoiaio_downloader_mac_rustbucket {
    meta:
        id = "5a003b68-ad9a-47f9-b157-dd898181dac2"
        version = "1.0"
        description = "RustBucket fake PDF reader"
        author = "Sekoia.io"
        creation_date = "2023-04-24"
        classification = "TLP:CLEAR"
        reference = "https://www.jamf.com/blog/bluenoroff-apt-targets-macos-rustbucket-malware/"
        hash1 = "38106b043ede31a66596299f17254d3f23cbe1f983674bf9ead5006e0f0bf880"
        hash2 = "bea33fb3205319868784c028418411ee796d6ee3dfe9309f143e7e8106116a49"
        hash3 = "7981ebf35b5eff8be2f3849c8f3085b9cec10d9759ff4d3afd46990520de0407"
        hash4 = "e74e8cdf887ae2de25590c55cb52dad66f0135ad4a1df224155f772554ea970c"
        
    strings:
        $down_exec1 = "_down_update_run" nocase
        $down_exec2 = "downAndExec" nocase
        $encrypt1 = "_encrypt_pdf"
        $encrypt2 = "_encrypt_data"
        $error_msg1 = "_alertErr"
        $error_msg2 = "_show_error_msg"
        $view_pdf1 = "-[PEPWindow view_pdf:]"
        $view_pdf2 = "-[PEPWindow viewPDF:]"
        $macho_magic = {CF FA ED FE}
        $java_magic = {CA FE BA BE}
        
    condition:
        ($macho_magic at 0 or $java_magic at 0) 
        and 5 of them
        and filesize > 50KB
}
        