from libs.transform import MaltegoTransform, MaltegoEntity
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from libs.config import config
from datetime import datetime
from dateutil import parser as duparse
import webbrowser
import ipaddress
import tempfile
import argparse
import requests
import json
import sys
import re
import os

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class Transform():

    def __init__(self):
        self.transform     = MaltegoTransform()
        self.value         = None
        self.parent_fields = self._additional_fields_to_dict()
        self.API_URL       = config["apis"]["virustotal"]["url"]
        self.API_KEY       = config["apis"]["virustotal"]["api_key"]
        self.limit_search = 300
        
    def _additional_fields_to_dict(self):
        """Translate additional fields to dict.

        Returns:
            dic: Dict containing parents fields.
        """
        rtn = {"parent.entity.value" : "", "entity.value" : ""}
        for i, field in enumerate(sys.argv[3].split("#")):
            field = field.split("=")
            if i == 0:
                rtn["entity.value"] = field[1]
            else:
                try:
                    rtn[field[0]] = field[1]
                except:
                    continue
        return rtn

    def _do_get_request(self, url):
        """Do a get request to the url and return the JSON.

        Args:
            url (str): the URL to query

        Returns:
            dict: Answer JSON as dict
        """
        try:
            print("<!--", url, "-->")
            return requests.get(url, verify=False, headers={"x-apikey" : self.API_KEY}).json()
        except:
            print("<!-- Issue with: ", url, "-->")
            self.transform.returnOutput()
            exit()

    def _reputation_to_color(self, i):
        """Some reputation (int) to color code.

        Args:
            i (int): reputation code

        Returns:
            str: color hex notation.
        """
        if i == 0:
            return "#7CFC00"
        elif i < 4:
            return "#ff7f00"
        elif i > 3:
            return "#ff0000"
            
    def download_sample(self):
        """Download a sample """
        
        try:
            url = f"{self.API_URL}files/{self.value}"
            res = requests.get(url).content
            fp = os.path.join(tempfile.gettempdir(), f"{self.value}.bin")
            with open(fp, "wb") as f:
                print(f"<!-- File downloaded under {fp} -->")
                f.write(res)
        except:
            print("<!-- Issue during the HTTP Request -->")
        self.transform.returnOutput()

    def open_in_browser(self):
        """Open a sample inside the Virustotal GUI via the browser instrumentation. """
        
        webbrowser.open_new_tab(f"https://www.virustotal.com/gui/file/{self.value}/details")
        self.transform.returnOutput()

    def search(self):
        """Search something in VT :) """
        
        search_value = self.value

        if "indicator.type" in self.parent_fields:
            if self.parent_fields["indicator.type"] == "trait":
                search_value = "content:{ " + self.value + " }"
            if self.parent_fields["indicator.type"] == "vhash":
                search_value = "vhash:" + self.value
            if self.parent_fields["indicator.type"] == "tlsh":
                search_value = "tlsh:" + self.value
            if self.parent_fields["indicator.type"] == "imphash":
                search_value = "imphash:" + self.value
            if self.parent_fields["indicator.type"] == "rich_pe_header_hash":
                search_value = "rich_pe_header_hash:" + self.value
            if self.parent_fields["indicator.type"] == "telfhash":
                search_value = "telfhash:" + self.value

        url = f"{self.API_URL}intelligence/search?query={search_value}&limit={self.limit_search}"
        res = self._do_get_request(url)

        if "data" in res:
            for obj in res["data"]:
                if obj["id"] != self.parent_fields["parent.entity.value"]:
                    if obj["type"] == "domain":
                        e = MaltegoEntity()
                        e.setType("maltego.Domain")
                        e.addAdditionalFields(fieldName="parent.entity.value",
                                            displayName="Parent Entity", 
                                            value=self.parent_fields["entity.value"])
                        e.setValue(obj["id"])
                        self.transform.addEntityToMessage(e)
                    elif obj["type"] == "ip": 
                        e = MaltegoEntity()
                        e.setType("maltego.IPv4Address")
                        e.addAdditionalFields(fieldName="parent.entity.value",
                                            displayName="Parent Entity", 
                                            value=self.parent_fields["entity.value"])
                        e.setValue(obj["id"])
                        self.transform.addEntityToMessage(e)
                    elif obj["type"] == "url":
                        e = MaltegoEntity()
                        e.setType("maltego.URL")
                        e.addAdditionalFields(fieldName="parent.entity.value",
                                            displayName="Parent Entity", 
                                            value=self.parent_fields["entity.value"])
                        e.addAdditionalFields(fieldName="url",
                                            displayName="URL", 
                                            value=obj["context_attributes"]["url"])
                        e.setValue(obj["context_attributes"]["url"])
                        self.transform.addEntityToMessage(e)
                    elif obj["type"] == "file":
                        e = MaltegoEntity()
                        e.setType("maltego.custom.file")
                        e.addAdditionalFields(fieldName="parent.entity.value",
                                            displayName="Parent Entity", 
                                            value=self.parent_fields["entity.value"])
                        try:
                            e.addAdditionalFields(fieldName="file.name",
                                            displayName="File Name", 
                                            value=obj["attributes"]["names"][0] if len(obj["attributes"]["names"]) else "")
                        except:
                            pass
                        try:
                            e.addAdditionalFields(fieldName="file.type",
                                            displayName="File Type", 
                                            value=obj["attributes"]["exiftool"]["MIMEType"])
                        except:
                            pass
                        try:
                            e.addAdditionalFields(fieldName="file.ssdeep",
                                            displayName="SSDeep", 
                                            value=obj["attributes"]["ssdeep"])
                        except:
                            pass
                        try:
                            e.addAdditionalFields(fieldName="file.md5",
                                            displayName="MD5", 
                                            value=obj["attributes"]["md5"])
                        except:
                            pass
                        try:
                            e.addAdditionalFields(fieldName="file.sha1",
                                            displayName="SHA1", 
                                            value=obj["attributes"]["sha1"])
                        except:
                            pass
                        try:
                            e.addAdditionalFields(fieldName="file.sha256",
                                            displayName="SHA256", 
                                            value=obj["attributes"]["sha256"])
                        except:
                            pass
                        try:
                            e.addAdditionalFields(fieldName="file.size",
                                            displayName="File size", 
                                            value=str(obj["attributes"]["size"]))
                        except:
                            pass
                        try:
                            e.addAdditionalFields(fieldName="file.magic",
                                            displayName="File magic", 
                                            value=obj["attributes"]["magic"])
                        except:
                            pass
                        try:
                            e.addAdditionalFields(fieldName="file.reputation",
                                            displayName="File reputation", 
                                            value=self._reputation_to_color(obj["attributes"]["last_analysis_stats"]["malicious"]))
                        except:
                            pass
                        e.setValue(obj["id"])
                        self.transform.addEntityToMessage(e)

        self.transform.returnOutput()

    ##
    ## Domain object 
    ##

    def domain_to_mx_records(self):
        """Get MX records of a domain. """

        url = f"{self.API_URL}domains/{self.value}"
        res = self._do_get_request(url)

        if "data" in res:
            if "attributes" in res["data"]:
                if "last_dns_records" in res["data"]["attributes"]:
                    for record in res["data"]["attributes"]["last_dns_records"]:
                        if record["type"] == "MX":
                            e = MaltegoEntity()
                            e.setType("maltego.MXRecord")
                            e.setValue(record["value"])
                            e.addAdditionalFields(fieldName="parent.entity.value",
                                                    displayName="Parent entity value", 
                                                    value=self.value)
                            e.setLinkLabel("MX record\nSeen on {}".format(datetime.fromtimestamp(res["data"]["attributes"]["last_dns_records_date"]).strftime("%Y-%m-%d")))
                            self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def domain_to_ns_records(self):
        """Get NS records of a domain. """

        url = f"{self.API_URL}domains/{self.value}"
        res = self._do_get_request(url)

        if "data" in res:
            if "attributes" in res["data"]:
                if "last_dns_records" in res["data"]["attributes"]:
                    for record in res["data"]["attributes"]["last_dns_records"]:
                        if record["type"] == "NS":
                            e = MaltegoEntity()
                            e.setType("maltego.NSRecord")
                            e.setValue(record["value"])
                            e.addAdditionalFields(fieldName="parent.entity.value",
                                                    displayName="Parent entity value", 
                                                    value=self.value)
                            e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                            e.setLinkLabel("NS record\nSeen on {}".format(datetime.fromtimestamp(res["data"]["attributes"]["last_dns_records_date"]).strftime("%Y-%m-%d")))
                            self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def domain_to_txt_records(self):
        """Get TXT records of a domain. """

        url = f"{self.API_URL}domains/{self.value}"
        res = self._do_get_request(url)

        if "data" in res:
            if "attributes" in res["data"]:
                if "last_dns_records" in res["data"]["attributes"]:
                    for record in res["data"]["attributes"]["last_dns_records"]:
                        if record["type"] == "TXT":
                            e = MaltegoEntity()
                            e.setType("maltego.Phrase")
                            e.setValue(record["value"])
                            e.addAdditionalFields(fieldName="parent.entity.value",
                                                    displayName="Parent entity value", 
                                                    value=self.value)
                            e.setLinkLabel("TXT record\nSeen on {}".format(datetime.fromtimestamp(res["data"]["attributes"]["last_dns_records_date"]).strftime("%Y-%m-%d")))
                            self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def domain_to_a_records(self):
        """Get A records of a domain. """

        url = f"{self.API_URL}domains/{self.value}"
        res = self._do_get_request(url)

        if "data" in res:
            if "attributes" in res["data"]:
                if "last_dns_records" in res["data"]["attributes"]:
                    for record in res["data"]["attributes"]["last_dns_records"]:
                        if record["type"] == "A":
                            e = MaltegoEntity()
                            e.setType("maltego.IPv4Address")
                            e.setValue(record["value"])
                            e.addAdditionalFields(fieldName="parent.entity.value",
                                                    displayName="Parent entity value", 
                                                    value=self.value)
                            e.setLinkLabel("A record\nSeen on {}".format(datetime.fromtimestamp(res["data"]["attributes"]["last_dns_records_date"]).strftime("%Y-%m-%d")))
                            self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def domain_to_aaaa_records(self):
        """Get AAAA records of a domain. """

        url = f"{self.API_URL}domains/{self.value}"
        res = self._do_get_request(url)

        if "data" in res:
            if "attributes" in res["data"]:
                if "last_dns_records" in res["data"]["attributes"]:
                    for record in res["data"]["attributes"]["last_dns_records"]:
                        if record["type"] == "AAAA":
                            e = MaltegoEntity()
                            e.setType("maltego.IPv6Address")
                            e.setValue(record["value"])
                            e.addAdditionalFields(fieldName="parent.entity.value",
                                                    displayName="Parent entity value", 
                                                    value=self.value)
                            e.setLinkLabel("AAAA record\nSeen on {}".format(datetime.fromtimestamp(res["data"]["attributes"]["last_dns_records_date"]).strftime("%Y-%m-%d")))
                            self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def domain_to_cname_records(self):
        """Get CNAME records of a domain. """

        url = f"{self.API_URL}domains/{self.value}"
        res = self._do_get_request(url)

        if "data" in res:
            if "attributes" in res["data"]:
                if "last_dns_records" in res["data"]["attributes"]:
                    for record in res["data"]["attributes"]["last_dns_records"]:
                        if record["type"] == "CNAME":
                            e = MaltegoEntity()
                            e.setType("maltego.DNSName")
                            e.setValue(record["value"])
                            e.addAdditionalFields(fieldName="parent.entity.value",
                                                    displayName="Parent entity value", 
                                                    value=self.value)
                            e.setLinkLabel("CNAME record\nSeen on {}".format(datetime.fromtimestamp(res["data"]["attributes"]["last_dns_records_date"]).strftime("%Y-%m-%d")))
                            self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def domain_to_creation_date(self):
        """Get creation date of a domain. """

        url = f"{self.API_URL}domains/{self.value}"
        res = self._do_get_request(url)

        if "data" in res:
            if "attributes" in res["data"]:
                if "creation_date" in res["data"]["attributes"]:
                    e = MaltegoEntity()
                    e.setType("maltego.DateTime")
                    e.setValue(datetime.fromtimestamp(res["data"]["attributes"]["creation_date"]).strftime("%Y-%m-%d"))
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent entity value", 
                                        value=self.value)
                    e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                    e.setLinkLabel("Creation date")
                    self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def domain_to_registrar(self):
        """Get domain registrar.
        """
        url = f"{self.API_URL}domains/{self.value}"
        res = self._do_get_request(url)

        if "data" in res:
            if "attributes" in res["data"]:
                if "registrar" in res["data"]["attributes"]:
                    e = MaltegoEntity()
                    e.setType("maltego.Company")
                    e.setValue(res["data"]["attributes"]["registrar"])
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent entity value", 
                                        value=self.value)
                    e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                    e.setLinkLabel("Registrar")
                    self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def domain_to_last_certificate(self):
        """Get last certificate associated to a domain. """

        url = f"{self.API_URL}domains/{self.value}"
        res = self._do_get_request(url)

        if "data" in res:
            if "attributes" in res["data"]:
                if "last_https_certificate" in res["data"]["attributes"]:
                    if "CN" in res["data"]["attributes"]["last_https_certificate"]["subject"]:
                        value = res["data"]["attributes"]["last_https_certificate"]["subject"]["CN"]
                        linkdesc = "Certificate CN\nSeen on {}".format(datetime.fromtimestamp(res["data"]["attributes"]["last_https_certificate_date"]).strftime("%Y-%M-%d"))
                    else:
                        value = res["data"]["attributes"]["last_https_certificate"]["serial_number"]
                        linkdesc = "Certificate SN\nSeen on {}".format(datetime.fromtimestamp(res["data"]["attributes"]["last_https_certificate_date"]).strftime("%Y-%M-%d"))
                    e = MaltegoEntity()
                    e.setType("maltego.X509Certificate")
                    e.setValue(value)
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent entity value", 
                                        value=self.value)
                    e.addAdditionalFields(fieldName="serial",
                                        displayName="Serial number", 
                                        value=res["data"]["attributes"]["last_https_certificate"]["serial_number"])
                    try:
                        e.addAdditionalFields(fieldName="issuer",
                                            displayName="Issuer", 
                                            value=res["data"]["attributes"]["last_https_certificate"]["issuer"]["O"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="thumbprint.sha256",
                                            displayName="Thumbprint SHA256", 
                                            value=res["data"]["attributes"]["last_https_certificate"]["thumbprint_sha256"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="thumbprint.sha1",
                                            displayName="Thumbprint SHA1", 
                                            value=res["data"]["attributes"]["last_https_certificate"]["thumbprint"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="valid.from",
                                            displayName="Valid from", 
                                            value=res["data"]["attributes"]["last_https_certificate"]["validity"]["not_before"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="valid.to",
                                            displayName="Valid to", 
                                            value=res["data"]["attributes"]["last_https_certificate"]["validity"]["not_after"])
                    except:
                        pass
                    e.setLinkLabel(linkdesc)
                    self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def domain_to_whois(self):
        """Get WHOIS record of a domain. """

        url = f"{self.API_URL}domains/{self.value}"
        res = self._do_get_request(url)

        if "data" in res:
            if "attributes" in res["data"]:
                if "whois" in res["data"]["attributes"]:
                    for line in res["data"]["attributes"]["whois"].splitlines():
                        line = line.strip()
                        if "Name Server:" in line:
                            e = MaltegoEntity()
                            e.setType("maltego.NSRecord")
                            e.setValue(line.split(" ")[-1].lower())
                            e.addAdditionalFields(fieldName="parent.entity.value",
                                                displayName="Parent entity value", 
                                                value=self.value)
                            e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                            self.transform.addEntityToMessage(e)
                        if "Registrar:" in line:
                            e = MaltegoEntity()
                            e.setType("maltego.Company")
                            e.setValue(line.replace("Registrar: ", ""))
                            e.addAdditionalFields(fieldName="parent.entity.value",
                                                displayName="Parent entity value", 
                                                value=self.value)
                            e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                            e.setLinkLabel("Registrar")
                            self.transform.addEntityToMessage(e)
                        if "Creation Date:" in line:
                            e = MaltegoEntity()
                            e.setType("maltego.DateTime")
                            e.setValue(duparse.parse(line.replace("Creation Date: ", "")).strftime("%Y-%m-%d") )
                            e.addAdditionalFields(fieldName="parent.entity.value",
                                                displayName="Parent entity value", 
                                                value=self.value)
                            e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                            e.setLinkLabel("Creation date")
                            self.transform.addEntityToMessage(e)
                        if "Registrant Email: " in line:
                            e = MaltegoEntity()
                            e.setType("maltego.EmailAddress")
                            e.setValue(line.replace("Registrant Email: ", ""))
                            e.addAdditionalFields(fieldName="parent.entity.value",
                                                displayName="Parent entity value", 
                                                value=self.value)
                            e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                            self.transform.addEntityToMessage(e)
                        if "Registrar Registration Expiration Date: " in line:
                            e = MaltegoEntity()
                            e.setType("maltego.DateTime")
                            e.setValue(duparse.parse(line.replace("Registrar Registration Expiration Date: ", "")).strftime("%Y-%m-%d") )
                            e.addAdditionalFields(fieldName="parent.entity.value",
                                                displayName="Parent entity value", 
                                                value=self.value)
                            e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                            e.setLinkLabel("Expiration date")
                            self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def domain_to_referrer_files(self):
        """Get files which refers to the domain. """

        urll = f"{self.API_URL}domains/{self.value}/referrer_files"
        res = self._do_get_request(url)

        if "data" in res:
            for obj in res["data"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.file")
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                try:
                    e.addAdditionalFields(fieldName="file.name",
                                        displayName="File Name", 
                                        value=obj["attributes"]["names"][0] if len(obj["attributes"]["names"]) else "")
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.type",
                                        displayName="File Type", 
                                        value=obj["attributes"]["exiftool"]["MIMEType"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.ssdeep",
                                        displayName="SSDeep", 
                                        value=obj["attributes"]["ssdeep"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.md5",
                                        displayName="MD5", 
                                        value=obj["attributes"]["md5"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.sha1",
                                        displayName="SHA1", 
                                        value=obj["attributes"]["sha1"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.sha256",
                                        displayName="SHA256", 
                                        value=obj["attributes"]["sha256"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.size",
                                        displayName="File size", 
                                        value=str(obj["attributes"]["size"]))
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.magic",
                                        displayName="File magic", 
                                        value=obj["attributes"]["magic"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.reputation",
                                        displayName="File reputation", 
                                        value=self._reputation_to_color(obj["attributes"]["last_analysis_stats"]["malicious"]))
                except:
                    pass
                e.setValue(obj["id"])
                e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                e.setLinkLabel("Contains strings refering to")
                
                self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def domain_to_communicating_files(self):
        """Get files which communicate to the domain. """

        url = f"{self.API_URL}domains/{self.value}/communicating_files"
        res = self._do_get_request(url)

        if "data" in res:
            for obj in res["data"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.file")
                try:
                    e.addAdditionalFields(fieldName="file.name",
                                        displayName="File Name", 
                                        value=obj["attributes"]["names"][0] if len(obj["attributes"]["names"]) else "")
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.type",
                                        displayName="File Type", 
                                        value=obj["attributes"]["exiftool"]["MIMEType"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.ssdeep",
                                        displayName="SSDeep", 
                                        value=obj["attributes"]["ssdeep"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.md5",
                                        displayName="MD5", 
                                        value=obj["attributes"]["md5"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.sha1",
                                        displayName="SHA1", 
                                        value=obj["attributes"]["sha1"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.sha256",
                                        displayName="SHA256", 
                                        value=obj["attributes"]["sha256"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.size",
                                        displayName="File size", 
                                        value=str(obj["attributes"]["size"]))
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.magic",
                                        displayName="File magic", 
                                        value=obj["attributes"]["magic"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.reputation",
                                        displayName="File reputation", 
                                        value=self._reputation_to_color(obj["attributes"]["last_analysis_stats"]["malicious"]))
                except:
                    pass
                e.addAdditionalFields(fieldName="file.reputation",
                                    displayName="File reputation", 
                                    value=self._reputation_to_color(obj["attributes"]["last_analysis_stats"]["malicious"]))

                e.setValue(obj["id"])
                e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                e.setLinkLabel("Communicates with")

                self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def domain_to_downloaded_files(self):
        """Get files downloaded from the domain. """

        url = f"{self.API_URL}domains/{self.value}/downloaded_files"
        res = self._do_get_request(url)

        if "data" in res:
            for obj in res["data"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.file")
                try:
                    e.addAdditionalFields(fieldName="file.name",
                                        displayName="File Name", 
                                        value=obj["attributes"]["names"][0] if len(obj["attributes"]["names"]) else "")
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.type",
                                        displayName="File Type", 
                                        value=obj["attributes"]["exiftool"]["MIMEType"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.ssdeep",
                                        displayName="SSDeep", 
                                        value=obj["attributes"]["ssdeep"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.md5",
                                        displayName="MD5", 
                                        value=obj["attributes"]["md5"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.sha1",
                                        displayName="SHA1", 
                                        value=obj["attributes"]["sha1"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.sha256",
                                        displayName="SHA256", 
                                        value=obj["attributes"]["sha256"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.size",
                                        displayName="File size", 
                                        value=str(obj["attributes"]["size"]))
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.magic",
                                        displayName="File magic", 
                                        value=obj["attributes"]["magic"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.reputation",
                                        displayName="File reputation", 
                                        value=self._reputation_to_color(obj["attributes"]["last_analysis_stats"]["malicious"]))
                except:
                    pass
                e.setValue(obj["id"])
                e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                e.setLinkLabel("Downloaded from")

                self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def domain_to_urls(self):
        """Get URLs associated to the domain. """

        url = f"{self.API_URL}domains/{self.value}/urls"
        res = self._do_get_request(url)

        if "data" in res:
            for obj in res["data"]:
                e = MaltegoEntity()
                e.setType("maltego.URL")
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="url",
                                    displayName="URL", 
                                    value=obj["attributes"]["url"])
                e.setValue(obj["attributes"]["url"])
                e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                e.setLinkLabel("URL\nSeen from {} to ".format(datetime.fromtimestamp(obj["attributes"]["first_submission_date"]).strftime("%Y-%M-%d"), datetime.fromtimestamp(obj["attributes"]["last_analysis_date"]).strftime("%Y-%m-%d")))
                
                self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def domain_to_fqdns(self):
        """ Get FQDNS linked to the domain. """

        url = f"{self.API_URL}domains/{self.value}/subdomains"
        res = self._do_get_request(url)

        if "data" in res:
            for obj in res["data"]:
                e = MaltegoEntity()
                e.setType("maltego.DNSName")
                e.setValue(obj["id"])
                self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    ##
    ## IP Address object
    ##

    def ip_to_cidr(self):
        """ Get CIDR linked to the IP address. """
        
        url = f"{self.API_URL}ip_addresses/{self.value}"
        res = self._do_get_request(url)

        if "data" in res:
            if "attributes" in res["data"]:
                e = MaltegoEntity()
                e.setType("maltego.CIDR")
                e.setValue(res["data"]["attributes"]["network"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent entity value", 
                                    value=self.value)
                e.addAdditionalFields(fieldName="company",
                                    displayName="Company", 
                                    value=res["data"]["attributes"]["as_owner"])
                e.addAdditionalFields(fieldName="asn",
                                    displayName="ASN", 
                                    value=str(res["data"]["attributes"]["asn"]))
                self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def ip_to_as(self):
        """ Get AS linked to the IP address. """
        
        url = f"{self.API_URL}ip_addresses/{self.value}"
        res = self._do_get_request(url)

        if "data" in res:
            if "attributes" in res["data"]:
                e = MaltegoEntity()
                e.setType("maltego.AS")
                e.setValue("AS" + str(res["data"]["attributes"]["asn"]))
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent entity value", 
                                    value=self.value)
                e.addAdditionalFields(fieldName="company",
                                    displayName="Company", 
                                    value=res["data"]["attributes"]["as_owner"])
                e.addAdditionalFields(fieldName="asn",
                                    displayName="ASN", 
                                    value=str(res["data"]["attributes"]["asn"]))
                self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def ip_to_company(self):
        """ Get company linked to the IP address. """
        
        url = f"{self.API_URL}ip_addresses/{self.value}"
        res = self._do_get_request(url)

        if "data" in res:
            if "attributes" in res["data"]:
                e = MaltegoEntity()
                e.setType("maltego.Company")
                e.setValue(res["data"]["attributes"]["as_owner"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent entity value", 
                                    value=self.value)
                e.addAdditionalFields(fieldName="company",
                                    displayName="Company", 
                                    value=res["data"]["attributes"]["as_owner"])
                e.addAdditionalFields(fieldName="asn",
                                    displayName="ASN", 
                                    value=str(res["data"]["attributes"]["asn"]))
                self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def ip_to_jarm(self):
        """ Get JARMs linked to the IP address. """
        
        url = f"{self.API_URL}ip_addresses/{self.value}"
        res = self._do_get_request(url)

        if "data" in res:
            if "attributes" in res["data"]:
                if "jarm" in res["data"]["attributes"]:
                    e = MaltegoEntity()
                    e.setType("maltego.custom.HostIndicator")
                    e.setValue(res["data"]["attributes"]["jarm"])
                    e.addAdditionalFields(fieldName="indicator.type",
                                        displayName="Indicator Type", 
                                        value="JARM hash")
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent entity value", 
                                    value=self.value)
                    e.setLinkLabel("Jarm hash")
                    self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def ip_to_last_certificate(self):
        """ Get last x509 certs linked to the IP address. """
        
        url = f"{self.API_URL}ip_addresses/{self.value}"
        res = self._do_get_request(url)

        if "data" in res:
            if "attributes" in res["data"]:
                if "last_https_certificate" in res["data"]["attributes"]:
                    if "CN" in res["data"]["attributes"]["last_https_certificate"]["subject"]:
                        value = res["data"]["attributes"]["last_https_certificate"]["subject"]["CN"]
                        linkdesc = "Certificate CN\nSeen on {}".format(datetime.fromtimestamp(res["data"]["attributes"]["last_https_certificate_date"]).strftime("%Y-%M-%d"))
                    else:
                        value = res["data"]["attributes"]["last_https_certificate"]["serial_number"]
                        linkdesc = "Certificate SN\nSeen on {}".format(datetime.fromtimestamp(res["data"]["attributes"]["last_https_certificate_date"]).strftime("%Y-%M-%d"))
                    e = MaltegoEntity()
                    e.setType("maltego.X509Certificate")
                    e.setValue(value)
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent entity value", 
                                        value=self.value)
                    e.addAdditionalFields(fieldName="serial",
                                        displayName="Serial number", 
                                        value=res["data"]["attributes"]["last_https_certificate"]["serial_number"])
                    try:
                        e.addAdditionalFields(fieldName="issuer",
                                            displayName="Issuer", 
                                            value=res["data"]["attributes"]["last_https_certificate"]["issuer"]["O"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="thumbprint.sha256",
                                            displayName="Thumbprint SHA256", 
                                            value=res["data"]["attributes"]["last_https_certificate"]["thumbprint_sha256"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="thumbprint.sha1",
                                            displayName="Thumbprint SHA1", 
                                            value=res["data"]["attributes"]["last_https_certificate"]["thumbprint"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="valid.from",
                                            displayName="Valid from", 
                                            value=res["data"]["attributes"]["last_https_certificate"]["validity"]["not_before"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="valid.to",
                                            displayName="Valid to", 
                                            value=res["data"]["attributes"]["last_https_certificate"]["validity"]["not_after"])
                    except:
                        pass
                    e.setLinkLabel(linkdesc)
                    self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def ip_to_historical_certificate(self):
        """ Get x509 certs linked to the IP address. """
        
        url = f"{self.API_URL}ip_addresses/{self.value}/historical_ssl_certificates"
        res = self._do_get_request(url)
        if "data" in res:
            for cert in res["data"]:
                e = MaltegoEntity()
                e.setType("maltego.X509Certificate")
                e.setValue(cert["id"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent entity value", 
                                    value=self.value)
                e.addAdditionalFields(fieldName="serial",
                                    displayName="Serial number", 
                                    value=cert["attributes"]["serial_number"])
                try:
                    e.addAdditionalFields(fieldName="issuer",
                                        displayName="Issuer", 
                                        value=cert["attributes"]["issuer"]["O"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="thumbprint.sha256",
                                        displayName="Thumbprint SHA256", 
                                        value=cert["attributes"]["thumbprint_sha256"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="thumbprint.sha1",
                                        displayName="Thumbprint SHA1", 
                                        value=cert["attributes"]["thumbprint"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="valid.from",
                                        displayName="Valid from", 
                                        value=cert["attributes"]["validity"]["not_before"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="valid.to",
                                        displayName="Valid to", 
                                        value=cert["attributes"]["validity"]["not_after"])
                except:
                    pass
                self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def ip_to_dnsnames(self):
        """ Get DNSNames linked to the IP address. """
        
        url = f"{self.API_URL}ip_addresses/{self.value}/resolutions"
        res = self._do_get_request(url)

        if "data" in res:
            for obj in res["data"]:
                e = MaltegoEntity()
                e.setType("maltego.DNSName")
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.setValue(obj["attributes"]["host_name"])
                e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                e.setLinkLabel("A record\nSeen on {}".format(datetime.fromtimestamp(obj["attributes"]["date"]).strftime("%Y-%m-%d")))
                
                self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def ip_to_urls(self):
        """ Get URLs linked to the IP address. """
        
        url = f"{self.API_URL}ip_addresses/{self.value}/urls"
        res = self._do_get_request(url)

        if "data" in res:
            for obj in res["data"]:
                e = MaltegoEntity()
                e.setType("maltego.URL")
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="url",
                                    displayName="URL", 
                                    value=obj["attributes"]["url"])
                e.setValue(obj["attributes"]["url"])
                e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                e.setLinkLabel("URL\nSeen from {} to ".format(datetime.fromtimestamp(obj["attributes"]["first_submission_date"]).strftime("%Y-%M-%d"), datetime.fromtimestamp(obj["attributes"]["last_analysis_date"]).strftime("%Y-%m-%d")))
                
                self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def ip_to_referrer_files(self):
        """ Get files which refer to the IP address. """
        
        url = f"{self.API_URL}ip_addresses/{self.value}/referrer_files"
        res = self._do_get_request(url)

        if "data" in res:
            for obj in res["data"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.file")
                try:
                    e.addAdditionalFields(fieldName="file.name",
                                    displayName="File Name", 
                                    value=obj["attributes"]["names"][0] if len(obj["attributes"]["names"]) else "")
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.type",
                                    displayName="File Type", 
                                    value=obj["attributes"]["exiftool"]["MIMEType"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.ssdeep",
                                    displayName="SSDeep", 
                                    value=obj["attributes"]["ssdeep"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.md5",
                                    displayName="MD5", 
                                    value=obj["attributes"]["md5"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.sha1",
                                    displayName="SHA1", 
                                    value=obj["attributes"]["sha1"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.sha256",
                                    displayName="SHA256", 
                                    value=obj["attributes"]["sha256"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.size",
                                    displayName="File size", 
                                    value=str(obj["attributes"]["size"]))
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.magic",
                                    displayName="File magic", 
                                    value=obj["attributes"]["magic"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.reputation",
                                    displayName="File reputation", 
                                    value=self._reputation_to_color(obj["attributes"]["last_analysis_stats"]["malicious"]))
                except:
                    pass    
                e.setValue(obj["id"])
                e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                e.setLinkLabel("Contains strings refering to")
                
                self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def ip_to_communicating_files(self):
        """ Get files which communicate to the IP address. """
        
        url = f"{self.API_URL}ip_addresses/{self.value}/communicating_files"
        res = self._do_get_request(url)

        if "data" in res:
            for obj in res["data"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.file")
                try:
                    e.addAdditionalFields(fieldName="file.name",
                                    displayName="File Name", 
                                    value=obj["attributes"]["names"][0] if len(obj["attributes"]["names"]) else "")
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.type",
                                    displayName="File Type", 
                                    value=obj["attributes"]["exiftool"]["MIMEType"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.ssdeep",
                                    displayName="SSDeep", 
                                    value=obj["attributes"]["ssdeep"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.md5",
                                    displayName="MD5", 
                                    value=obj["attributes"]["md5"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.sha1",
                                    displayName="SHA1", 
                                    value=obj["attributes"]["sha1"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.sha256",
                                    displayName="SHA256", 
                                    value=obj["attributes"]["sha256"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.size",
                                    displayName="File size", 
                                    value=str(obj["attributes"]["size"]))
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.magic",
                                    displayName="File magic", 
                                    value=obj["attributes"]["magic"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.reputation",
                                    displayName="File reputation", 
                                    value=self._reputation_to_color(obj["attributes"]["last_analysis_stats"]["malicious"]))
                except:
                    pass
                e.setValue(obj["id"])
                e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                e.setLinkLabel("Communicates with")

                self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    def ip_to_downloaded_files(self):
        """ Get files downloaded from the IP address. """

        url = f"{self.API_URL}ip_addresses/{self.value}/downloaded_files"
        res = self._do_get_request(url)

        if "data" in res:
            for obj in res["data"]:
                e = MaltegoEntity()
                e.setType("maltego.custom.file")
                try:
                    e.addAdditionalFields(fieldName="file.name",
                                    displayName="File Name", 
                                    value=obj["attributes"]["names"][0] if len(obj["attributes"]["names"]) else "")
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.type",
                                    displayName="File Type", 
                                    value=obj["attributes"]["exiftool"]["MIMEType"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.ssdeep",
                                    displayName="SSDeep", 
                                    value=obj["attributes"]["ssdeep"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.md5",
                                    displayName="MD5", 
                                    value=obj["attributes"]["md5"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.sha1",
                                    displayName="SHA1", 
                                    value=obj["attributes"]["sha1"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.sha256",
                                    displayName="SHA256", 
                                    value=obj["attributes"]["sha256"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.size",
                                    displayName="File size", 
                                    value=str(obj["attributes"]["size"]))
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.magic",
                                    displayName="File magic", 
                                    value=obj["attributes"]["magic"])
                except:
                    pass
                try:
                    e.addAdditionalFields(fieldName="file.reputation",
                                    displayName="File reputation", 
                                    value=self._reputation_to_color(obj["attributes"]["last_analysis_stats"]["malicious"]))
                except:
                    pass
                e.setValue(obj["id"])
                e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                e.setLinkLabel("Downloaded from")

                self.transform.addEntityToMessage(e)
        self.transform.returnOutput()

    ##
    ## URL object
    ##

    def url_to_communicating_files(self):
        """ Get files communicating to the URL. """
        
        try:
            url = f"{self.API_URL}intelligence/search?query={self.value}&limit={self.limit_search}"
            res = self._do_get_request(url)
            url_id = res["data"][0]["id"]
            
            url = f"{self.API_URL}urls/{url_id}/communicating_files"
            res = self._do_get_request(url)

            if "data" in res:
                for obj in res["data"]:
                    e = MaltegoEntity()
                    e.setType("maltego.custom.file")
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                    try:
                        e.addAdditionalFields(fieldName="file.name",
                                        displayName="File Name", 
                                        value=obj["attributes"]["names"][0] if len(obj["attributes"]["names"]) else "")
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.type",
                                        displayName="File Type", 
                                        value=obj["attributes"]["exiftool"]["MIMEType"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.ssdeep",
                                        displayName="SSDeep", 
                                        value=obj["attributes"]["ssdeep"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.md5",
                                        displayName="MD5", 
                                        value=obj["attributes"]["md5"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.sha1",
                                        displayName="SHA1", 
                                        value=obj["attributes"]["sha1"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.sha256",
                                        displayName="SHA256", 
                                        value=obj["attributes"]["sha256"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.size",
                                        displayName="File size", 
                                        value=str(obj["attributes"]["size"]))
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.magic",
                                        displayName="File magic", 
                                        value=obj["attributes"]["magic"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.reputation",
                                        displayName="File reputation", 
                                        value=self._reputation_to_color(obj["attributes"]["last_analysis_stats"]["malicious"]))
                    except:
                        pass
                    e.setValue(obj["id"])
                    e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                    e.setLinkLabel("Communicates with")

                    self.transform.addEntityToMessage(e)
        except:
            pass
        self.transform.returnOutput()

    def url_to_downloaded_files(self):
        """ Get files downloaded from the URL. """
        
        try:
            url = f"{self.API_URL}intelligence/search?query={self.value}&limit={self.limit_search}"
            res = self._do_get_request(url)
            url_id = res["data"][0]["id"]

            url = f"{self.API_URL}urls/{url_id}/downloaded_files"
            res = self._do_get_request(url)

            if "data" in res:
                for obj in res["data"]:
                    e = MaltegoEntity()
                    e.setType("maltego.custom.file")
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                    e.addAdditionalFields(fieldName="file.name",
                                        displayName="File Name", 
                                        value=obj["attributes"]["names"][0] if len(obj["attributes"]["names"]) else "")
                    try:
                        e.addAdditionalFields(fieldName="file.type",
                                        displayName="File Type", 
                                        value=obj["attributes"]["exiftool"]["MIMEType"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.ssdeep",
                                        displayName="SSDeep", 
                                        value=obj["attributes"]["ssdeep"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.md5",
                                        displayName="MD5", 
                                        value=obj["attributes"]["md5"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.sha1",
                                        displayName="SHA1", 
                                        value=obj["attributes"]["sha1"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.sha256",
                                        displayName="SHA256", 
                                        value=obj["attributes"]["sha256"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.size",
                                        displayName="File size", 
                                        value=str(obj["attributes"]["size"]))
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.magic",
                                        displayName="File magic", 
                                        value=obj["attributes"]["magic"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.reputation",
                                        displayName="File reputation", 
                                        value=self._reputation_to_color(obj["attributes"]["last_analysis_stats"]["malicious"]))
                    except:
                        pass
                    e.setValue(obj["id"])
                    e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                    e.setLinkLabel("Downloaded from")
                    self.transform.addEntityToMessage(e)
        except:
            pass
        self.transform.returnOutput()

    def url_to_embedded_js_files(self):
        """ Get URLs embedded in JS files. """
        
        try:
            url = f"{self.API_URL}intelligence/search?query={self.value}&limit={self.limit_search}"
            res = self._do_get_request(url)
            url_id = res["data"][0]["id"]

            url = f"{self.API_URL}urls/{url_id}/embedded_js_files"
            res = self._do_get_request(url)

            if "data" in res:
                for obj in res["data"]:
                    e = MaltegoEntity()
                    e.setType("maltego.custom.file")
                    
                    e.setValue(obj["id"])
                    e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                    e.setLinkLabel("Embedded in")

                    self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()
    

    def url_to_redirecting_urls(self):
        """ Get URLs redirecting which redirects to the URL"""
        
        try:
            url = f"{self.API_URL}intelligence/search?query={self.value}&limit={self.limit_search}"
            res = self._do_get_request(url)
            url_id = res["data"][0]["id"]

            url = f"{self.API_URL}urls/{url_id}/redirecting_urls"
            res = self._do_get_request(url)

            if "data" in res:
                for obj in res["data"]:
                    e = MaltegoEntity()
                    e.setType("maltego.URL")
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                    e.addAdditionalFields(fieldName="url",
                                        displayName="URL", 
                                        value=obj["attributes"]["url"])
                    e.setValue(obj["url"])
                    e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                    e.setLinkLabel("Redirects to")
                    self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()


    def url_to_redirects_to(self):
        """ Get where the URL is redirecting. """
        
        try:
            url = f"{self.API_URL}intelligence/search?query={self.value}&limit={self.limit_search}"
            res = self._do_get_request(url)
            url_id = res["data"][0]["id"]

            url = f"{self.API_URL}urls/{url_id}/redirects_to"
            res = self._do_get_request(url)

            if "data" in res:
                for obj in res["data"]:
                    e = MaltegoEntity()
                    e.setType("maltego.URL")
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                    e.addAdditionalFields(fieldName="url",
                                        displayName="URL", 
                                        value=obj["attributes"]["url"])
                    e.setValue(obj["url"])
                    e.setLinkLabel("Redirects to")
                    self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()


    def url_to_referrer_files(self):
        """ Get files which refer to the URL. """

        try:
            url = f"{self.API_URL}intelligence/search?query={self.value}&limit={self.limit_search}"
            res = self._do_get_request(url)
            url_id = res["data"][0]["id"]
            
            url = f"{self.API_URL}urls/{url_id}/referrer_files"
            res = self._do_get_request(url)

            if "data" in res:
                for obj in res["data"]:
                    e = MaltegoEntity()
                    e.setType("maltego.custom.file")
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                    e.addAdditionalFields(fieldName="file.name",
                                        displayName="File Name", 
                                        value=obj["attributes"]["names"][0] if len(obj["attributes"]["names"]) else "")
                    try:
                        e.addAdditionalFields(fieldName="file.type",
                                        displayName="File Type", 
                                        value=obj["attributes"]["exiftool"]["MIMEType"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.ssdeep",
                                        displayName="SSDeep", 
                                        value=obj["attributes"]["ssdeep"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.md5",
                                        displayName="MD5", 
                                        value=obj["attributes"]["md5"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.sha1",
                                        displayName="SHA1", 
                                        value=obj["attributes"]["sha1"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.sha256",
                                        displayName="SHA256", 
                                        value=obj["attributes"]["sha256"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.size",
                                        displayName="File size", 
                                        value=str(obj["attributes"]["size"]))
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.magic",
                                        displayName="File magic", 
                                        value=obj["attributes"]["magic"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.reputation",
                                        displayName="File reputation", 
                                        value=self._reputation_to_color(obj["attributes"]["last_analysis_stats"]["malicious"]))
                    except:
                        pass
                    e.setValue(obj["id"])
                    e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                    e.setLinkLabel("Refers to")
                    
                    self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()


    def url_to_referrer_urls(self):
        """ Get URLs which refer to the URL. """
        
        try:
            url = f"{self.API_URL}intelligence/search?query={self.value}&limit={self.limit_search}"
            res = self._do_get_request(url)
            url_id = res["data"][0]["id"]
            
            url = f"{self.API_URL}urls/{url_id}/referrer_urls"
            res = self._do_get_request(url)

            if "data" in res:
                for obj in res["data"]:
                    e = MaltegoEntity()
                    e.setType("maltego.URL")
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                    e.addAdditionalFields(fieldName="url",
                                        displayName="URL", 
                                        value=obj["context_attributes"]["url"])
                    e.setValue(obj["context_attributes"]["url"])
                    e.setLinkLabel("Refers to")
                    e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                    self.transform.addEntityToMessage(e)
        except:
            pass
        
        self.transform.returnOutput()


    def url_to_last_serving_ip_address(self):
        """ Get last IP address served by the URL. """
        
        try:
            url = f"{self.API_URL}intelligence/search?query={self.value}&limit={self.limit_search}"
            res = self._do_get_request(url)
            url_id = res["data"][0]["id"]
            
            url = f"{self.API_URL}urls/{url_id}/last_serving_ip_address"
            res = self._do_get_request(url)

            if "data" in res:
                ip_address = res["data"]["id"]
                ip = ipaddress.ip_address(ip_address)
                if "IPv4Address" in str(type(ip)):
                    iptype = "IPv4Address"
                else:
                    iptype = "IPv6Address"
                e = MaltegoEntity()
                e.setType("maltego.{}".format(iptype))
                e.setValue(ip_address)
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.setLinkLabel("Last serving IP")
                self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def url_to_network_location(self):
        """ Get the network location of the URL. """
        
        try:
            url = f"{self.API_URL}intelligence/search?query={self.value}&limit={self.limit_search}"
            res = self._do_get_request(url)
            url_id = res["data"][0]["id"]
            
            url = f"{self.API_URL}urls/{url_id}/network_location"
            res = self._do_get_request(url)

            if "data" in res:
                host = res["data"]["id"]
                try:
                    x = ipaddress.ip_address(host)
                    if "IPv4Address" in str(type(x)):
                        hosttype = "IPv4Address"
                    else:
                        hosttype = "IPv6Address"
                except:
                    hosttype = "DNSName"

                e = MaltegoEntity()
                e.setType("maltego.{}".format(hosttype))
                e.setValue(host)
                e.addAdditionalFields(fieldName="parent.entity.value",
                                    displayName="Parent Entity", 
                                    value=self.parent_fields["entity.value"])
                e.setLinkLabel("Extracted host")
                self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()


    ##
    ## File object 
    ##

    def file_to_vhash(self):
        """ Get the vhash of a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}"
            res = self._do_get_request(url)

            if "data" in res:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileIndicator")
                e.setValue(res["data"]["attributes"]["vhash"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                      displayName="Parent Entity", 
                                      value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="indicator.type",
                                      displayName="Indicator type", 
                                      value="vhash")
                e.setLinkLabel("VHASH")
                self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_tlsh(self):
        """ Get the TLSH of a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}"
            res = self._do_get_request(url)

            if "data" in res:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileIndicator")
                e.setValue(res["data"]["attributes"]["tlsh"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                      displayName="Parent Entity", 
                                      value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="indicator.type",
                                      displayName="Indicator type", 
                                      value="tlsh")
                e.setLinkLabel("TLSH")
                self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_telfhash(self):
        """ Get the TELFH of a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}"
            res = self._do_get_request(url)

            if "data" in res:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileIndicator")
                e.setValue(res["data"]["attributes"]["telfhash"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                      displayName="Parent Entity", 
                                      value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="indicator.type",
                                      displayName="Indicator type", 
                                      value="telfhash")
                e.setLinkLabel("TELFHASH")
                self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_authentihash(self):
        """ Get the Authentihash of a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}"
            res = self._do_get_request(url)

            if "data" in res:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileIndicator")
                e.setValue(res["data"]["attributes"]["authentihash"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                      displayName="Parent Entity", 
                                      value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="indicator.type",
                                      displayName="Indicator type", 
                                      value="authentihash")
                e.setLinkLabel("Authentihash")
                self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_md5(self):
        """ Get the MD5 of a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}"
            res = self._do_get_request(url)

            if "data" in res:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileIndicator")
                e.setValue(res["data"]["attributes"]["md5"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                      displayName="Parent Entity", 
                                      value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="indicator.type",
                                      displayName="Indicator type", 
                                      value="md5")
                e.setLinkLabel("MD5")
                self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_sha1(self):
        """ Get the SHA1 of a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}"
            res = self._do_get_request(url)

            if "data" in res:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileIndicator")
                e.setValue(res["data"]["attributes"]["sha1"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                      displayName="Parent Entity", 
                                      value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="indicator.type",
                                      displayName="Indicator type", 
                                      value="sha1")
                e.setLinkLabel("SHA1")
                self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_sha256(self):
        """ Get the SHA256 of a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}"
            res = self._do_get_request(url)

            if "data" in res:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileIndicator")
                e.setValue(res["data"]["attributes"]["sha256"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                      displayName="Parent Entity", 
                                      value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="indicator.type",
                                      displayName="Indicator type", 
                                      value="sha256")
                e.setLinkLabel("SHA256")
                self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_sha512(self):
        """ Get the SHA512 of a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}"
            res = self._do_get_request(url)

            if "data" in res:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileIndicator")
                e.setValue(res["data"]["attributes"]["sha512"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                      displayName="Parent Entity", 
                                      value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="indicator.type",
                                      displayName="Indicator type", 
                                      value="sha512")
                e.setLinkLabel("SHA512")
                self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()


    def file_to_filenames(self):
        """ Get the filenames of a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}"
            res = self._do_get_request(url)

            if "data" in res:
                for n in res["data"]["attributes"]["names"]:
                    e = MaltegoEntity()
                    e.setType("maltego.custom.FileIndicator")
                    e.setValue(n)
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                    e.addAdditionalFields(fieldName="indicator.type",
                                        displayName="Indicator type", 
                                        value="name")
                    e.setLinkLabel("SHA512")
                    self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_creation_date(self):
        """ Get the creation date of a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}"
            res = self._do_get_request(url)

            if "data" in res:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileIndicator")
                e.setValue(res["data"]["attributes"]["creation_date"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                      displayName="Parent Entity", 
                                      value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="indicator.type",
                                      displayName="Indicator type", 
                                      value="creation_date")
                e.setLinkLabel("Creation date")
                self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_last_modification_date(self):
        """ Get the last modification date of a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}"
            res = self._do_get_request(url)

            if "data" in res:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileIndicator")
                e.setValue(res["data"]["attributes"]["last_modification_date"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                      displayName="Parent Entity", 
                                      value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="indicator.type",
                                      displayName="Indicator type", 
                                      value="last_modification_date")
                e.setLinkLabel("Last modification date")
                self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_submitters(self):
        """ Get the file submitters. """
        
        try:

            url = f"{self.API_URL}files/{self.value}"
            res = self._do_get_request(url)

            if "data" in res:
                for sub in res["data"]:
                    e = MaltegoEntity()
                    e.setType("maltego.Alias")
                    e.setValue(sub["attributes"]["source_key"])
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                    e.addAdditionalFields(fieldName="country",
                                          displayName="Country", 
                                          value=sub["attributes"]["country"])
                    e.setLinkLabel("Submitted via {} on the\n {}".format(sub["attributes"]["interface"], datetime.fromtimestamp(sub["attributes"]["date"])))
                    e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                    self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_contacted_domains(self):
        """ Get the contacted domains of a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}/contacted_domains"
            res = self._do_get_request(url)

            if "data" in res:
                for data in res["data"]:
                    e = MaltegoEntity()
                    e.setType("maltego.DNSName")
                    e.setValue(data["id"])
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                    e.setLinkLabel("Make DNS request to")
                    self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_contacted_urls(self):
        """ Get the contacted URLs of a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}/contacted_urls"
            res = self._do_get_request(url)

            if "data" in res:
                for data in res["data"]:
                    e = MaltegoEntity()
                    e.setType("maltego.URL")
                    e.setValue(data["context_attributes"]["url"])
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                    e.addAdditionalFields(fieldName="url",
                                    displayName="URL", 
                                    value=data["context_attributes"]["url"])
                    e.setLinkLabel("Browse that URL")
                    self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_contacted_ips(self):
        """ Get the contacted IPs of a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}/contacted_ips"
            res = self._do_get_request(url)

            if "data" in res:
                for data in res["data"]:
                    e = MaltegoEntity()

                    try:
                        ip = ipaddress.ip_address(data["id"])
                        if "IPv4Address" in type(ip):
                            type = "IPv4Address"
                        else:
                            type = "IPv6Address"
                    except:
                        type = "IPv4Address"

                    e.setType("maltego.{}".format(type))
                    e.setValue(data["id"])
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                    e.setLinkLabel("Make network request to")
                    self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_embedded_urls(self):
        """ Get the URLs embedded in a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}/embedded_urls"
            res = self._do_get_request(url)

            if "data" in res:
                for data in res["data"]:
                    e = MaltegoEntity()
                    e.setType("maltego.URL")
                    e.setValue(data["context_attributes"]["url"])
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                    e.addAdditionalFields(fieldName="url",
                                    displayName="URL", 
                                    value=data["context_attributes"]["url"])
                    e.setLinkLabel("Embbed this indicator")
                    self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_embedded_ips(self):
        """ Get the IPs embedded in a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}/embedded_ips"
            res = self._do_get_request(url)

            if "data" in res:
                for data in res["data"]:
                    e = MaltegoEntity()

                    try:
                        ip = ipaddress.ip_address(data["id"])
                        if "IPv4Address" in type(ip):
                            type = "IPv4Address"
                        else:
                            type = "IPv6Address"
                    except:
                        type = "IPv4Address"

                    e.setType("maltego.{}".format(type))
                    e.setValue(data["id"])
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                    e.setLinkLabel("Embbed this indicator")
                    self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_embedded_domains(self):
        """ Get the DNSNames embedded in a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}/embedded_domains"
            res = self._do_get_request(url)

            if "data" in res:
                for data in res["data"]:
                    e = MaltegoEntity()
                    e.setType("maltego.DNSName")
                    e.setValue(data["id"])
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                    e.setLinkLabel("Embbed this indicator")
                    self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_dropped_files(self):
        """ Get the files dropped by a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}/dropped_files"
            res = self._do_get_request(url)

            if "data" in res:
                for obj in res["data"]:
                    e = MaltegoEntity()
                    e.setType("maltego.custom.file")
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                    e.addAdditionalFields(fieldName="file.name",
                                        displayName="File Name", 
                                        value=obj["attributes"]["names"][0] if len(obj["attributes"]["names"]) else "")
                    try:
                        e.addAdditionalFields(fieldName="file.type",
                                        displayName="File Type", 
                                        value=obj["attributes"]["exiftool"]["MIMEType"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.ssdeep",
                                        displayName="SSDeep", 
                                        value=obj["attributes"]["ssdeep"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.md5",
                                        displayName="MD5", 
                                        value=obj["attributes"]["md5"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.sha1",
                                        displayName="SHA1", 
                                        value=obj["attributes"]["sha1"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.sha256",
                                        displayName="SHA256", 
                                        value=obj["attributes"]["sha256"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.size",
                                        displayName="File size", 
                                        value=str(obj["attributes"]["size"]))
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.magic",
                                        displayName="File magic", 
                                        value=obj["attributes"]["magic"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.reputation",
                                        displayName="File reputation", 
                                        value=self._reputation_to_color(obj["attributes"]["last_analysis_stats"]["malicious"]))
                    except:
                        pass
                    e.setValue(obj["id"])
                    e.setLinkLabel("Drops")
                    
                    self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()


    def file_to_execution_parents(self):
        """ Get execution parents of a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}/execution_parents"
            res = self._do_get_request(url)

            if "data" in res:
                for obj in res["data"]:
                    e = MaltegoEntity()
                    e.setType("maltego.custom.file")
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                    e.addAdditionalFields(fieldName="file.name",
                                        displayName="File Name", 
                                        value=obj["attributes"]["names"][0] if len(obj["attributes"]["names"]) else "")
                    try:
                        e.addAdditionalFields(fieldName="file.type",
                                        displayName="File Type", 
                                        value=obj["attributes"]["exiftool"]["MIMEType"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.ssdeep",
                                        displayName="SSDeep", 
                                        value=obj["attributes"]["ssdeep"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.md5",
                                        displayName="MD5", 
                                        value=obj["attributes"]["md5"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.sha1",
                                        displayName="SHA1", 
                                        value=obj["attributes"]["sha1"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.sha256",
                                        displayName="SHA256", 
                                        value=obj["attributes"]["sha256"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.size",
                                        displayName="File size", 
                                        value=str(obj["attributes"]["size"]))
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.magic",
                                        displayName="File magic", 
                                        value=obj["attributes"]["magic"])
                    except:
                        pass
                    try:
                        e.addAdditionalFields(fieldName="file.reputation",
                                        displayName="File reputation", 
                                        value=self._reputation_to_color(obj["attributes"]["last_analysis_stats"]["malicious"]))
                    except:
                        pass
                    e.setValue(obj["id"])
                    e.setLinkLabel("Execute or drops")
                    e.addAdditionalFields('link#maltego.link.direction','link#maltego.link.direction','loose','output-to-input')
                   
                    self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_magic(self):
        """ Get the magic of a file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}"
            res = self._do_get_request(url)

            if "data" in res:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileIndicator")
                e.setValue(res["data"]["attributes"]["magic"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                      displayName="Parent Entity", 
                                      value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="indicator.type",
                                      displayName="Indicator type", 
                                      value="magic")
                e.setLinkLabel("magic")
                self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_rich_pe_header_hash(self):
        """ Get the hash realted to the Rich header of a PE file. """
        
        try:

            url = f"{self.API_URL}files/{self.value}"
            res = self._do_get_request(url)

            if "data" in res:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileIndicator")
                e.setValue(res["data"]["attributes"]["pe_info"]["rich_pe_header_hash"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                      displayName="Parent Entity", 
                                      value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="indicator.type",
                                      displayName="Indicator type", 
                                      value="rich_pe_header_hash")
                e.setLinkLabel("Rich Header")
                self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_imphash(self):
        """ Get the Imphash of a PE file. """
        
        url = f"{self.API_URL}files/{self.value}"
        res = self._do_get_request(url)
        try:
            if "data" in res:
                e = MaltegoEntity()
                e.setType("maltego.custom.FileIndicator")
                e.setValue(res["data"]["attributes"]["pe_info"]["imphash"])
                e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                e.addAdditionalFields(fieldName="indicator.type",
                                        displayName="Indicator type", 
                                        value="imphash")
                e.setLinkLabel("ImpHash")
                self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

    def file_to_sections(self):
        """ Get the sections of a file. """
        
        try:
            url = f"{self.API_URL}files/{self.value}"
            res = self._do_get_request(url)

            if "data" in res:
                for section in res["data"]["attributes"]["pe_info"]["sections"]:
                    e = MaltegoEntity()
                    e.setType("maltego.custom.FileIndicator")
                    e.setValue(section["md5"])
                    e.addAdditionalFields(fieldName="parent.entity.value",
                                        displayName="Parent Entity", 
                                        value=self.parent_fields["entity.value"])
                    e.addAdditionalFields(fieldName="indicator.type",
                                        displayName="Indicator type", 
                                        value="sectionmd5")
                    e.setNote(json.dumps(section, indent=1))
                    e.setLinkLabel("Section")
                    self.transform.addEntityToMessage(e)
        except:
            pass

        self.transform.returnOutput()

parser = argparse.ArgumentParser()
parser.add_argument('--method', type=str, help='The method to ask')
args = parser.parse_known_args()

method = args[0].method

t = Transform()
t.value = args[1][0].strip()

if re.match("[a-zA-Z\_]+", method):
    eval("t.%s()" % (method))
