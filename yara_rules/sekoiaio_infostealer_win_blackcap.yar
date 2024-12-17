rule sekoiaio_infostealer_win_blackcap {
    meta:
        id = "1aa1fadb-3413-46e2-b733-1ad2134f7be2"
        version = "1.0"
        description = "Finds BlackCap Grabber samples (Python code obfuscated using Py-Fuscate)"
        author = "Sekoia.io"
        creation_date = "2023-03-06"
        classification = "TLP:CLEAR"
        
    strings:
        $imp01 = "import asyncio, json, ntpath, random, re, shutil, sqlite3, subprocess, threading, winreg, zipfile, httpx, psutil, win32gui, win32con, pyperclip, base64, requests, ctypes, time" ascii
        $imp02 = "from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer;from Crypto.Cipher import AES;from PIL import ImageGrab;from win32crypt import CryptUnprotectData" ascii
        
        $pyf01 = "import marshal,lzma,gzip,bz2,binascii,zlib;exec(marshal.loads(binascii.a2b_base64(b'YwAAAAAA" ascii
        
    condition:
        ($imp01 in (0..500) and $pyf01 in (@imp01+200..@imp01+1000) or $imp02 in (0..1000) and $pyf01 in (@imp02+100..@imp02+500)) and
        filesize > 100KB and filesize < 500KB
}
        