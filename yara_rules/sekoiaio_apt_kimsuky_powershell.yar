rule sekoiaio_apt_kimsuky_powershell {
    meta:
        id = "b7f812e0-d08b-40fe-908a-dc5765d6bc66"
        version = "1.0"
        description = "Powershell scripts used by Kimsuky. If size < 3KB ok. If between 3 and 15, a check is needed"
        author = "Sekoia.io"
        creation_date = "2024-09-23"
        classification = "TLP:CLEAR"
        hash = "6babb53d881448dc58dd7c32fcd4208a"
        hash = "29ec7a4495ea512d44d33c9847893200"
        hash = "fde68771cebd7ecd81721b0dff5b7869"
        hash = "0c3fd7f45688d5ddb9f0107877ce2fbd"
        hash = "1a1723be720c1d9cd57cf4a6a112df79"
        
    strings:
        $ = ".ToCharArray();[array]::Reverse(" ascii
        $ = ");$res = -join ($bytes -as [char[]]);Invoke-Expression $res;" ascii
        
    condition:
        all of them and filesize < 15KB
}
        