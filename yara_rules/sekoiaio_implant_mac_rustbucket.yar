rule sekoiaio_implant_mac_rustbucket {
    meta:
        id = "fcbb745d-7f56-4c51-9db5-427da22a0c68"
        version = "1.0"
        description = "Detect the RustBucket malware"
        source = "Sekoia.io"
        creation_date = "2023-04-24"
        classification = "TLP:CLEAR"
        hash = "9ca914b1cfa8c0ba021b9e00bda71f36cad132f27cf16bda6d937badee66c747"
        reference = "https://www.jamf.com/blog/bluenoroff-apt-targets-macos-rustbucket-malware/"
        
    strings:
        $ = "/Users/hero/"
        $ = "PATHIpv6Ipv4Bodyslotpath"
        $macho_magic = {CF FA ED FE}
        $java_magic = {CA FE BA BE}
        
    condition:
        ($macho_magic at 0 or $java_magic at 0) 
        and all of them
}
        