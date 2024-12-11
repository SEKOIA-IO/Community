rule sekoiaio_apt_aridviper_rustsysjoker {
    meta:
        id = "14ff3f76-0371-4b45-9864-bf69c74e60aa"
        version = "1.0"
        description = "Detects Rust Sysjoker variant via PDB path or key and Rust string"
        source = "Sekoia.io"
        creation_date = "2023-11-27"
        classification = "TLP:CLEAR"
        
    strings:
        
        $Rust = "called `Option::unwrap()` on a `None` value"
        $Key = "QQL8VJUJMABL8H5YNRC9QNEOHA"
        $PDB = "C:\\Code\\Rust\\RustDown-Belal\\target\\release\\deps\\RustDown.pdb"
        
    condition:
        uint16be(0) == 0x4d5a and filesize < 1MB and ($PDB or ($Rust and $Key))
}
        