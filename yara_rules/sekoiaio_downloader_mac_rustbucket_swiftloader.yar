rule sekoiaio_downloader_mac_rustbucket_swiftloader {
    meta:
        id = "bdbc95db-5d58-4c96-91f9-34b653e67f50"
        version = "1.0"
        description = "Detect the file com.EdoneViewer in the new version of RustBucker 2023-10"
        source = "Sekoia.io"
        creation_date = "2023-12-05"
        classification = "TLP:CLEAR"
        hash1 = "7c5bf60787bfd076c8806eaa4f1185f5b9fda69008376624ab3d17f207eb16a4"
        hash2 = "bc90adde92bd47b4de7d384e5b20c1a1791d603629bd0fcba4b550fb35e93216"
        hash3 = "c9a7b42c7b29ca948160f95f017e9e9ae781f3b981ecf6edbac943e52c63ffc8"
        
    strings:
        $ = "/Users/ghost/Desktop/EdoneViewer/EdoneViewer/"
        $ = "EdoneViewerApp.swift"
        
    condition:
        1 of them
}
        