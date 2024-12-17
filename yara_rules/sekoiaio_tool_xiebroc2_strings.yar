rule sekoiaio_tool_xiebroc2_strings {
    meta:
        id = "8451878e-5371-440b-b8ac-f9e6f7643d3c"
        version = "1.0"
        description = "Detects XiebroC2 based on strings"
        author = "Sekoia.io"
        creation_date = "2024-09-11"
        classification = "TLP:CLEAR"
        hash = "84e665bcbf963a2cf67d879aa3422d79"
        hash = "3558c376420724694ba244a2e2acd20c"
        hash = "e29fb9cd825db51a7a2e519f188e61ba"
        hash = "a3b31739ad5eed51277c8478a83160a3"
        hash = "d6e2499ea7fe8f047da1a95dae16d2c3"
        hash = "1616818b65bf49d985bb1816461a4a75"
        hash = "2e72d3ef2492088a4623d77d5e419ab8"
        hash = "351770f860507d652ec3644ed1988f7f"
        hash = "58fa6ad96028753ba8b0b0ed8fa6dccb"
        hash = "607b541525b27eeefbef1455397bff35"
        hash = "c2a242612468814e2e951e4db3762059"
        hash = "431e275f4e43ec4ef7c2cc8ba126e9d3"
        hash = "ace54bd32c226a7b9a6d4d53791e4021"
        hash = "f22c21ed7bba1ddfc42ffdc66da3a4dd"
        hash = "9a5ff9e07ed04cb0e71102cf1aae380c"
        hash = "d20e01a1af3f40a7a9646d7e7df1b42e"
        hash = "5544b621c9772cd32c4db77a0e59515a"
        
    strings:
        $s1 = "RemarkClientColor"
        $s2 = "HandlePacket"
        $s3 = "-hide"
        $s4 = "Failed to send data:"
        $s5 = "Pac_ket"
        $s6 = "WANip"
        $s7 = "%s %s && Kernel: %s"
        $g1 = "go.buildid"
        $g2 = "dep    golang.org"
        
    condition:
        3 of ($s*) and any of ($g*)
}
        