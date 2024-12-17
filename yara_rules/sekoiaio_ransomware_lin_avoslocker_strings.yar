rule sekoiaio_ransomware_lin_avoslocker_strings {
    meta:
        version = "1.0"
        description = "Detect AvosLocker ransomware for Linux by using strings from its ransom note and the onion domains"
        author = "Sekoia.io"
        creation_date = "2022-02-21"
        classification = "TLP:CLEAR"
        hash1 = "0cd7b6ea8857ce827180342a1c955e79c3336a6cf2000244e5cfd4279c5fc1b6"
        hash2 = "7c935dcd672c4854495f41008120288e8e1c144089f1f06a23bd0a0f52a544b1"
        hash3 = "10ab76cd6d6b50d26fde5fe54e8d80fceeb744de8dbafddff470939fac6a98c4"
        id = "6056e15c-d656-41cb-bea0-704776c52c92"
        
    strings:
        $s1 = "The corporations whom don't pay or fail to respond in a swift manner can be found in our blog, accessible at" ascii
        $s2 = "http://avosqxh72b5ia23dl5fgwcpndkctuzqvh2iefk5imp3pi5gfhel5klad.onion" ascii
        $s3 = "http://avosjon4pfh3y7ew3jdwz6ofw7lljcxlbk7hcxxmnxlh5kvf2akcqjad.onion" ascii
        
    condition:
        uint32(0)==0x464c457f and all of them
}
        