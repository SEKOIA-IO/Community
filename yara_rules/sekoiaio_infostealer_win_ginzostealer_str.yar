rule sekoiaio_infostealer_win_ginzostealer_str {
    meta:
        id = "ef87e94b-9c53-44b4-b8a1-87d371a6d2cb"
        version = "1.0"
        description = "Finds samples of the Ginzo Stealer"
        author = "Sekoia.io"
        reference = "https://blog.talosintelligence.com/2022/04/haskers-gang-zingostealer.html"
        creation_date = "2022-04-21"
        classification = "TLP:CLEAR"
        
    strings:
        $str0 = "Ginzo.pdb" ascii
        $str1 = "Ginzo.exe" wide
        $str2 = "SELECT creation_utc,top_frame_site_key,host_key,name,value,encrypted_value,path,expires_utc,is_secure,is_httponly,last_access_utc,has_expires,is_persistent,priority,samesite,source_scheme,source_port,is_same_party FROM cookies" wide
        $str3 = "SELECT origin_url,action_url,username_element,username_value,password_element,password_value,submit_element,signon_realm,date_created,blacklisted_by_user,scheme,password_type,times_used,form_data,display_name,icon_url,federation_url,skip_zero_click,generation_upload_status,possible_username_pairs,id,date_last_used,moving_blocked_for,date_password_modified FROM logins" wide
        $str4 = "SELECT id,originAttributes,name,value,host,path,expiry,lastAccessed,creationTime,isSecure,isHttpOnly,inBrowserElement,sameSite,rawSameSite,schemeMap FROM moz_cookies" wide
        
    condition:
        uint16(0)==0x5A4D and 4 of them
}
        